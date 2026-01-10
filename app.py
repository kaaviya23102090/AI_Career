from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from groq import Groq
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'edutor-pro-ultra-secure-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///edutor.db'
db = SQLAlchemy(app)

client = Groq(api_key="")

login_manager = LoginManager(app)
login_manager.login_view = 'auth_page'

otp_store = {}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    # Relationship to link chat history to the user
    messages = db.relationship('ChatHistory', backref='owner', lazy=True)

class ChatHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(10), nullable=False) # 'user' or 'ai'
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(uid): return User.query.get(int(uid))

@app.route('/')
def auth_page(): return render_template('auth.html')

@app.route('/dashboard')
@login_required
def dashboard(): return render_template('chatbot.html')

# --- NEW HISTORY API ENDPOINTS ---

@app.route('/api/get-history', methods=['GET'])
@login_required
def get_history():
    history = ChatHistory.query.filter_by(user_id=current_user.id).all()
    return jsonify([{"role": h.role, "content": h.content} for h in history])

@app.route('/api/save-message', methods=['POST'])
@login_required
def save_message():
    data = request.json
    new_msg = ChatHistory(role=data['role'], content=data['content'], user_id=current_user.id)
    db.session.add(new_msg)
    db.session.commit()
    return jsonify({"status": "success"})

@app.route('/api/clear-history', methods=['POST'])
@login_required
def clear_history():
    ChatHistory.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    return jsonify({"msg": "History Cleared"})

# --- EXISTING AUTH & LOGIC ---

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"msg": "Account name already exist, choose someother name"}), 409
    new_user = User(email=email, password=generate_password_hash(data['password']))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "Account Created Successfully"})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        login_user(user)
        return jsonify({"msg": "Success"})
    return jsonify({"msg": "Invalid Credentials"}), 401

@app.route('/api/send-otp', methods=['POST'])
def send_otp():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg": "No account found. Create one with a password first."}), 403
    otp = str(random.randint(100000, 999999))
    otp_store[email] = otp
    return jsonify({"msg": "OTP Generated", "otp": otp})

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    email, otp = data.get('email'), data.get('otp')
    if email in otp_store and otp_store[email] == otp:
        user = User.query.filter_by(email=email).first()
        login_user(user)
        del otp_store[email]
        return jsonify({"msg": "Success"})
    return jsonify({"msg": "Invalid OTP"}), 401

@app.route('/api/rephrase', methods=['POST'])
@login_required
def rephrase():
    text = request.json.get("text")
    completion = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "system", "content": "Professional resume rephraser. Use high-impact verbs. Keep it short."},
                  {"role": "user", "content": text}]
    )
    return jsonify({"rephrased": completion.choices[0].message.content})

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    data = request.json
    mode = data.get("mode", "mentor")
    user_msg = data.get("message")
    
    if mode == "resume":
        sys_prompt = "Generate a professional resume based on the Michael Harris template style ( Sydney Australia style). Use clean HTML/Inline CSS (white background, black text). NO MARKDOWN, only pure HTML elements for the resume body."
    else:
        sys_prompt = "You are a professional AI Career Mentor."

    completion = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "system", "content": sys_prompt}, {"role": "user", "content": user_msg}]
    )
    return jsonify({"reply": completion.choices[0].message.content})

@app.route('/logout')
def logout(): logout_user(); return redirect(url_for('auth_page'))

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True)
