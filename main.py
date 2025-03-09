from flask import Flask, render_template, request, jsonify, json, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grocery_store.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    orders = db.relationship('Order', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(200))

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    order_items = db.relationship('OrderItem', backref='product', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'price': self.price,
            'quantity': self.quantity,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

    def check_stock_level(self):
        threshold = int(Config.query.filter_by(key='critical_stock_threshold').first().value)
        if self.quantity <= threshold:
            return True
        return False

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_ordered = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Routes for web interface
@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart_items = request.json.get('items', [])
    
    # Create new order
    order = Order(user_id=current_user.id)
    db.session.add(order)
    
    for item in cart_items:
        product = Product.query.get_or_404(item['product_id'])
        if product.quantity < item['quantity']:
            return jsonify({'error': f'Insufficient stock for {product.name}'}), 400
            
        # Update product quantity
        product.quantity -= item['quantity']
        
        # Add order item
        order_item = OrderItem(
            order_id=order.id,
            product_id=product.id,
            quantity=item['quantity']
        )
        db.session.add(order_item)
        
        # Check if stock is critically low
        if product.check_stock_level():
            flash(f'Warning: {product.name} is running low on stock!')
    
    db.session.commit()
    return jsonify({'message': 'Order placed successfully'})

# Admin routes
@app.route('/admin/products/add', methods=['GET', 'POST'])
@login_required
def add_product():
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        new_product = Product(
            name=request.form['name'],
            price=float(request.form['price']),
            quantity=int(request.form['quantity'])
        )
        db.session.add(new_product)
        db.session.commit()
        
        return redirect(url_for('index'))
    return render_template('admin/add_product.html')

@app.route('/admin/products/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(id):
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('index'))
        
    product = Product.query.get_or_404(id)
    
    if request.method == 'POST':
        product.name = request.form['name']
        product.price = float(request.form['price'])
        product.quantity = int(request.form['quantity'])
        db.session.commit()
        
        if product.check_stock_level():
            flash(f'Warning: {product.name} is running low on stock!')
            
        return redirect(url_for('index'))
    return render_template('admin/edit_product.html', product=product)

@app.route('/admin/products/<int:id>/delete')
@login_required
def delete_product(id):
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('index'))
        
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()
    return redirect(url_for('index'))

# API Routes
@app.route('/api/products', methods=['GET'])
@login_required
def get_products():
    products = Product.query.all()
    return jsonify([product.to_dict() for product in products])

@app.route('/api/products/<int:id>', methods=['GET'])
@login_required
def get_product(id):
    product = Product.query.get_or_404(id)
    return jsonify(product.to_dict())

@app.route('/api/products/<int:id>', methods=['PUT'])
@login_required
def update_product(id):
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
        
    product = Product.query.get_or_404(id)
    data = request.get_json()
    
    product.name = data.get('name', product.name)
    product.price = float(data.get('price', product.price))
    product.quantity = int(data.get('quantity', product.quantity))
    
    db.session.commit()
    
    if product.check_stock_level():
        return jsonify({
            'product': product.to_dict(),
            'warning': f'Warning: {product.name} is running low on stock!'
        })
    return jsonify(product.to_dict())

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()  # Commit admin user first
            
        # Set critical stock threshold
        if not Config.query.filter_by(key='critical_stock_threshold').first():
            threshold = Config(key='critical_stock_threshold', value='10')
            db.session.add(threshold)
            db.session.commit()  # Commit config separately
            
        # Check for low stock items on startup
        low_stock = Product.query.filter(Product.quantity <= 10).all()
        if low_stock:
            print("WARNING: The following items are low in stock:")
            for item in low_stock:
                print(f"- {item.name}: {item.quantity} remaining")
    
    app.run(debug=True)
