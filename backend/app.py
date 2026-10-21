import os, re, time, secrets
from functools import wraps
from decimal import Decimal, InvalidOperation
from flask import Flask, request, jsonify
from flask_cors import CORS
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import mysql.connector
from mysql.connector import Error
import cloudinary
import cloudinary.uploader
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB request cap; multiple images supported
origins = [x.strip() for x in os.getenv('CORS_ORIGINS', '*').split(',') if x.strip()]
CORS(app, resources={r'/api/*': {'origins': origins}}, supports_credentials=False)

SECRET = os.getenv('SECRET_KEY', '')
USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
PASSWORD = os.getenv('ADMIN_PASSWORD', '')
serializer = URLSafeTimedSerializer(SECRET or 'development-only-change-this')
CLOUD_NAME = os.getenv('CLOUDINARY_CLOUD_NAME', '')
CLOUD_KEY = os.getenv('CLOUDINARY_API_KEY', '')
CLOUD_SECRET = os.getenv('CLOUDINARY_API_SECRET', '')
if CLOUD_NAME and CLOUD_KEY and CLOUD_SECRET:
    cloudinary.config(cloud_name=CLOUD_NAME, api_key=CLOUD_KEY, api_secret=CLOUD_SECRET, secure=True)

CATEGORIES = {'sofas-living','beds-bedroom','dining-gathering','office-furniture','kitchen-furniture','storage-furniture','other'}
ALLOWED_EXTENSIONS = {'jpg','jpeg','png','webp','avif'}

def db_connect():
    cfg = {
        'host': os.getenv('DB_HOST'), 'port': int(os.getenv('DB_PORT', '3306')),
        'user': os.getenv('DB_USER'), 'password': os.getenv('DB_PASSWORD'),
        'database': os.getenv('DB_NAME', 'defaultdb'), 'connection_timeout': 10,
        'autocommit': False,
    }
    ca = os.getenv('DB_SSL_CA', '').strip()
    if ca:
        cfg['ssl_ca'] = ca
        cfg['ssl_verify_cert'] = True
    else:
        cfg['ssl_disabled'] = False
    missing = [k for k in ('host','user','password') if not cfg.get(k)]
    if missing:
        raise RuntimeError('Database environment variables missing: ' + ', '.join(missing))
    last = None
    for attempt in range(3):
        try:
            return mysql.connector.connect(**cfg)
        except Error as e:
            last = e
            if attempt < 2:
                time.sleep(0.6 * (attempt + 1))
    raise last

def ensure_schema():
    con = db_connect()
    try:
        cur = con.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS products (
          id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          name VARCHAR(180) NOT NULL, category VARCHAR(80) NOT NULL,
          description TEXT NULL, price DECIMAL(12,2) NULL,
          image_url VARCHAR(2048) NOT NULL, cloudinary_public_id VARCHAR(255) NOT NULL,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          INDEX idx_products_category (category), INDEX idx_products_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')
        con.commit(); cur.close()
    finally: con.close()

def token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
        if not token: return jsonify({'error':'Please log in again.'}), 401
        try: data = serializer.loads(token, max_age=60 * 60 * 12)
        except (BadSignature, SignatureExpired): return jsonify({'error':'Session expired. Please log in again.'}), 401
        if data.get('role') != 'admin': return jsonify({'error':'Not authorized.'}), 403
        return fn(*args, **kwargs)
    return wrapper

def product_dict(row):
    return {'id': row[0], 'name': row[1], 'category': row[2], 'description': row[3] or '',
            'price': float(row[4]) if row[4] is not None else None, 'image_url': row[5],
            'cloudinary_public_id': row[6], 'created_at': str(row[7]) if row[7] else ''}

def clean_name(value, fallback='Furniture item'):
    value = re.sub(r'\s+', ' ', (value or '').strip())
    return value[:180] or fallback

def valid_image(file):
    name = (file.filename or '').lower()
    ext = name.rsplit('.',1)[-1] if '.' in name else ''
    return ext in ALLOWED_EXTENSIONS

@app.get('/api/health')
def health():
    return jsonify({'status':'ok','service':'sve-api'})

@app.post('/api/login')
def login():
    data = request.get_json(silent=True) or {}
    if not PASSWORD or not SECRET:
        return jsonify({'error':'Admin credentials are not configured on the server.'}), 503
    if secrets.compare_digest(str(data.get('username','')), USERNAME) and secrets.compare_digest(str(data.get('password','')), PASSWORD):
        return jsonify({'token': serializer.dumps({'role':'admin','sub':USERNAME}), 'expires_in':43200})
    return jsonify({'error':'Incorrect username or password.'}), 401

@app.get('/api/categories')
def categories():
    return jsonify({'categories': sorted(CATEGORIES)})

@app.get('/api/products')
def list_products():
    category = request.args.get('category','').strip()
    search = request.args.get('search','').strip()[:100]
    try:
        con = db_connect(); cur = con.cursor()
        sql = 'SELECT id,name,category,description,price,image_url,cloudinary_public_id,created_at FROM products'
        clauses=[]; params=[]
        if category and category in CATEGORIES: clauses.append('category=%s'); params.append(category)
        if search: clauses.append('(name LIKE %s OR description LIKE %s)'); params += [f'%{search}%',f'%{search}%']
        if clauses: sql += ' WHERE ' + ' AND '.join(clauses)
        sql += ' ORDER BY created_at DESC, id DESC LIMIT 1000'
        cur.execute(sql, tuple(params)); rows=cur.fetchall()
        return jsonify({'products':[product_dict(r) for r in rows], 'count':len(rows)})
    except Exception as e:
        app.logger.exception('List products failed')
        return jsonify({'error':'Could not load products. Check database configuration.'}), 503
    finally:
        try: cur.close(); con.close()
        except Exception: pass

@app.post('/api/products')
@token_required
def create_products():
    if not (CLOUD_NAME and CLOUD_KEY and CLOUD_SECRET): return jsonify({'error':'Cloudinary is not configured on the server.'}), 503
    files = request.files.getlist('images')
    if not files: return jsonify({'error':'Choose at least one image.'}), 400
    if len(files) > 100: return jsonify({'error':'Upload at most 100 images per batch.'}), 400
    category = request.form.get('category','').strip()
    if category not in CATEGORIES: return jsonify({'error':'Choose a valid category.'}), 400
    description = (request.form.get('description') or '').strip()[:5000]
    raw_price = (request.form.get('price') or '').strip()
    price = None
    if raw_price:
        try:
            price = Decimal(raw_price)
            if price < 0: raise InvalidOperation()
        except (InvalidOperation, ValueError): return jsonify({'error':'Price must be a valid non-negative number.'}), 400
    uploaded=[]; errors=[]
    try:
        con = db_connect(); cur = con.cursor()
        for file in files:
            if not file.filename: continue
            if not valid_image(file):
                errors.append({'filename':file.filename,'error':'Use JPG, PNG, WEBP or AVIF images.'}); continue
            public_id=None
            try:
                result=cloudinary.uploader.upload(file, folder=f'sve/{category}', resource_type='image', unique_filename=True, overwrite=False)
                public_id=result['public_id']
                name=clean_name(os.path.splitext(file.filename)[0])
                cur.execute('INSERT INTO products (name,category,description,price,image_url,cloudinary_public_id) VALUES (%s,%s,%s,%s,%s,%s)',
                    (name,category,description,price,result['secure_url'],public_id))
                uploaded.append({'name':name,'category':category,'image_url':result['secure_url']})
            except Exception as e:
                if public_id:
                    try: cloudinary.uploader.destroy(public_id, resource_type='image')
                    except Exception: pass
                app.logger.exception('Upload failed for %s', file.filename)
                errors.append({'filename':file.filename,'error':'Upload failed. Check Cloudinary configuration and retry.'})
        con.commit()
        return jsonify({'message':f'{len(uploaded)} image(s) uploaded.','uploaded':uploaded,'errors':errors,'uploaded_count':len(uploaded),'error_count':len(errors)}), 201 if uploaded else 400
    except Exception:
        app.logger.exception('Bulk upload failed')
        try: con.rollback()
        except Exception: pass
        return jsonify({'error':'Bulk upload could not be completed. Check database and Cloudinary settings.'}), 503
    finally:
        try: cur.close(); con.close()
        except Exception: pass

@app.delete('/api/products')
@token_required
def delete_products():
    data=request.get_json(silent=True) or {}
    ids=data.get('ids')
    if not isinstance(ids,list) or not ids: return jsonify({'error':'Select at least one product.'}),400
    if len(ids)>1000: return jsonify({'error':'Delete at most 1000 products at a time.'}),400
    try: ids=list(dict.fromkeys(int(x) for x in ids if str(x).isdigit()))
    except Exception: return jsonify({'error':'Invalid product IDs.'}),400
    if not ids: return jsonify({'error':'No valid product IDs selected.'}),400
    con=db_connect(); cur=con.cursor()
    try:
        placeholders=','.join(['%s']*len(ids))
        cur.execute(f'SELECT id,cloudinary_public_id FROM products WHERE id IN ({placeholders})',tuple(ids))
        rows=cur.fetchall()
        cur.execute(f'DELETE FROM products WHERE id IN ({placeholders})',tuple(ids)); con.commit()
        removed=cur.rowcount
        cloud_errors=0
        if CLOUD_NAME and CLOUD_KEY and CLOUD_SECRET:
            for _,public_id in rows:
                try: cloudinary.uploader.destroy(public_id, resource_type='image')
                except Exception:
                    cloud_errors+=1; app.logger.exception('Could not remove Cloudinary asset %s', public_id)
        return jsonify({'message':f'{removed} product(s) removed from the database.','deleted_count':removed,'cloudinary_errors':cloud_errors})
    except Exception:
        con.rollback(); app.logger.exception('Bulk delete failed')
        return jsonify({'error':'Bulk delete failed. Please retry.'}),503
    finally: cur.close(); con.close()

@app.put('/api/products/<int:product_id>')
@token_required
def update_product(product_id):
    data=request.get_json(silent=True) or {}
    name=clean_name(data.get('name'))
    category=(data.get('category') or '').strip()
    description=(data.get('description') or '').strip()[:5000]
    price=data.get('price')
    if category not in CATEGORIES: return jsonify({'error':'Choose a valid category.'}),400
    try: price=Decimal(str(price)) if price not in (None,'') else None
    except (InvalidOperation,ValueError): return jsonify({'error':'Invalid price.'}),400
    con=db_connect();cur=con.cursor()
    try:
        cur.execute('UPDATE products SET name=%s,category=%s,description=%s,price=%s WHERE id=%s',(name,category,description,price,product_id)); con.commit()
        if cur.rowcount==0: return jsonify({'error':'Product not found or unchanged.'}),404
        return jsonify({'message':'Product updated.'})
    except Exception:
        con.rollback();app.logger.exception('Update failed');return jsonify({'error':'Could not update product.'}),503
    finally:cur.close();con.close()

@app.errorhandler(413)
def too_large(_): return jsonify({'error':'The upload is too large. Try smaller batches.'}),413

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT','5000')), debug=False)
