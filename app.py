from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__, template_folder='templates')

# Configurações de segurança importantes
app.secret_key = os.urandom(24)  # Chave secreta aleatória
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Em produção, use HTTPS
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # Sessão expira em 1 hora

# Configuração do banco de dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    todos = db.relationship('Todo', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Modelo de Tarefa
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'completed': self.completed
        }

# Middleware para verificar autenticação
@app.before_request
def check_auth():
    # Lista de rotas que não requerem autenticação
    open_routes = ['login_page', 'register_page', 'login', 'register', 'static']
    
    if request.endpoint not in open_routes and 'user_id' not in session:
        return redirect(url_for('login_page'))

# Rotas de Autenticação
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Dados incompletos'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Nome de usuário já existe'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email já cadastrado'}), 400

    user = User(username=data['username'], email=data['email'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'Usuário registrado com sucesso'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Dados incompletos'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Usuário ou senha inválidos'}), 401

    session['user_id'] = user.id
    return jsonify({'message': 'Login bem-sucedido'}), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logout bem-sucedido'}), 200

# Rotas de Tarefas (protegidas)
@app.route('/api/todos', methods=['GET'])
def get_todos():
    todos = Todo.query.filter_by(user_id=session['user_id']).all()
    return jsonify([todo.to_dict() for todo in todos])

@app.route('/api/todos', methods=['POST'])
def add_todo():
    data = request.get_json()
    
    if not data or 'title' not in data:
        return jsonify({'error': 'Título é obrigatório'}), 400
    
    todo = Todo(
        title=data['title'],
        description=data.get('description', ''),
        completed=False,
        user_id=session['user_id']
    )
    
    db.session.add(todo)
    db.session.commit()
    return jsonify(todo.to_dict()), 201

@app.route('/api/todos/<int:id>', methods=['GET'])
def get_todo(id):
    todo = Todo.query.filter_by(id=id, user_id=session['user_id']).first_or_404()
    return jsonify(todo.to_dict())

@app.route('/api/todos/<int:id>', methods=['PUT'])
def update_todo(id):
    todo = Todo.query.filter_by(id=id, user_id=session['user_id']).first_or_404()
    data = request.get_json()
    
    if 'title' in data:
        todo.title = data['title']
    if 'description' in data:
        todo.description = data['description']
    if 'completed' in data:
        todo.completed = data['completed']
    
    db.session.commit()
    return jsonify(todo.to_dict())

@app.route('/api/todos/<int:id>', methods=['DELETE'])
def delete_todo(id):
    todo = Todo.query.filter_by(id=id, user_id=session['user_id']).first_or_404()
    db.session.delete(todo)
    db.session.commit()
    return jsonify({'message': 'Tarefa removida com sucesso'})

# Rotas de Páginas
@app.route('/')
def index():
    # Verifica se o usuário está autenticado
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

# Rota de health check
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy'})

# Inicialização do banco de dados
def init_db():
    with app.app_context():
        db.create_all()
        # Criar um usuário de teste se não existir
        if not User.query.filter_by(username='test').first():
            test_user = User(username='test', email='test@example.com')
            test_user.set_password('test123')
            db.session.add(test_user)
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)