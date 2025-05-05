from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import timedelta

app = Flask(__name__, template_folder='templates')

# ===============================================
# CONFIGURAÇÕES DO BANCO DE DADOS MYSQL
# ===============================================
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:123456789@localhost/taskflow_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_RECYCLE'] = 299
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 20

# ===============================================
# CONFIGURAÇÕES DE SEGURANÇA
# ===============================================
app.secret_key = os.urandom(24)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Inicializa extensões
db = SQLAlchemy(app)
CORS(app)

# ===============================================
# MODELOS DO BANCO DE DADOS (ATUALIZADOS)
# ===============================================
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)  # Aumentado para 256 caracteres
    todos = db.relationship('Todo', backref='user', lazy=True)

    def set_password(self, password):
        # Usando método de hash que gera string mais curta
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Todo(db.Model):
    __tablename__ = 'todos'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'completed': self.completed
        }

# ===============================================
# MIDDLEWARE DE AUTENTICAÇÃO
# ===============================================
@app.before_request
def check_auth():
    open_routes = ['login_page', 'register_page', 'login', 'register', 'static', 'health']
    if request.endpoint not in open_routes and 'user_id' not in session:
        return redirect(url_for('login_page'))

# ===============================================
# ROTAS DE AUTENTICAÇÃO
# ===============================================
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Dados incompletos'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Nome de usuário já existe'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email já cadastrado'}), 400
    
    new_user = User(username=data['username'], email=data['email'])
    new_user.set_password(data['password'])
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Usuário registrado com sucesso'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Erro ao registrar usuário', 'details': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Dados incompletos'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Usuário ou senha inválidos'}), 401
    
    session['user_id'] = user.id
    return jsonify({
        'message': 'Login bem-sucedido',
        'user': {'id': user.id, 'username': user.username, 'email': user.email}
    }), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logout bem-sucedido'}), 200

# ===============================================
# ROTAS DE TAREFAS
# ===============================================
@app.route('/api/todos', methods=['GET'])
def get_todos():
    try:
        todos = Todo.query.filter_by(user_id=session['user_id']).all()
        return jsonify([todo.to_dict() for todo in todos])
    except Exception as e:
        return jsonify({'error': 'Erro ao buscar tarefas', 'details': str(e)}), 500

@app.route('/api/todos', methods=['POST'])
def add_todo():
    data = request.get_json()
    if not data or 'title' not in data:
        return jsonify({'error': 'Título é obrigatório'}), 400
    
    new_todo = Todo(
        title=data['title'],
        description=data.get('description', ''),
        completed=False,
        user_id=session['user_id']
    )
    
    try:
        db.session.add(new_todo)
        db.session.commit()
        return jsonify(new_todo.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Erro ao criar tarefa', 'details': str(e)}), 500

@app.route('/api/todos/<int:todo_id>', methods=['GET'])
def get_todo(todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=session['user_id']).first()
    if not todo:
        return jsonify({'error': 'Tarefa não encontrada'}), 404
    return jsonify(todo.to_dict())

@app.route('/api/todos/<int:todo_id>', methods=['PUT'])
def update_todo(todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=session['user_id']).first()
    if not todo:
        return jsonify({'error': 'Tarefa não encontrada'}), 404
    
    data = request.get_json()
    if 'title' in data:
        todo.title = data['title']
    if 'description' in data:
        todo.description = data['description']
    if 'completed' in data:
        todo.completed = data['completed']
    
    try:
        db.session.commit()
        return jsonify(todo.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Erro ao atualizar tarefa', 'details': str(e)}), 500

@app.route('/api/todos/<int:todo_id>', methods=['DELETE'])
def delete_todo(todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=session['user_id']).first()
    if not todo:
        return jsonify({'error': 'Tarefa não encontrada'}), 404
    
    try:
        db.session.delete(todo)
        db.session.commit()
        return jsonify({'message': 'Tarefa excluída com sucesso'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Erro ao excluir tarefa', 'details': str(e)}), 500

# ===============================================
# ROTAS DE PÁGINAS
# ===============================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/health')
def health_check():
    try:
        db.session.execute('SELECT 1')
        return jsonify({'status': 'healthy', 'database': 'connected'})
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'database': 'disconnected', 'error': str(e)}), 500

# ===============================================
# INICIALIZAÇÃO DO BANCO DE DADOS
# ===============================================
def init_db():
    with app.app_context():
        # Remove todas as tabelas existentes
        db.drop_all()
        
        # Cria novas tabelas com a estrutura atualizada
        db.create_all()
        
        # Cria usuário de teste com senha mais curta
        if not User.query.filter_by(username='test').first():
            test_user = User(username='test', email='test@example.com')
            test_user.set_password('test123')  # Senha simples para teste
            db.session.add(test_user)
            db.session.commit()
            print("✅ Banco de dados inicializado com usuário de teste")

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)