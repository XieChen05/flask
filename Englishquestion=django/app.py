
# 删除单个激活码
# 一键删除所有激活码
from flask import Flask, jsonify, request, send_from_directory
import os
import sqlite3
import random
import string
from datetime import datetime
import json  # 用于 AI 接口 payload 序列化

app = Flask(__name__)

# 本地SQLite数据库文件路径
LOCAL_DB_PATH = 'english_question.db'

# 初始化本地SQLite数据库
def init_db():
    conn = sqlite3.connect(LOCAL_DB_PATH)
    c = conn.cursor()
    with open('schema.sql', 'r') as f:
        c.executescript(f.read())
    conn.commit()
    conn.close()


# 初始化数据库并插入默认管理员账号
def init_admin():
    conn = sqlite3.connect(LOCAL_DB_PATH)
    c = conn.cursor()
    # 检查是否有管理员账号
    c.execute("SELECT 1 FROM users WHERE username = ? AND is_admin = 1", ("admin",))
    if not c.fetchone():
        # 插入默认管理员账号 admin/admin123
        c.execute("INSERT INTO users (username, password, is_admin, created_at) VALUES (?, ?, 1, datetime('now'))", ("admin", "admin123"))
        conn.commit()
    conn.close()

init_db()
init_admin()

# 静态文件目录
STATIC_FOLDER = 'static'
if not os.path.exists(STATIC_FOLDER):
    os.makedirs(STATIC_FOLDER)

# 页面路由
@app.route('/')
def index():
    return send_from_directory('.', 'english.html')

@app.route('/admin')
def admin():
    return send_from_directory('.', 'admin.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(STATIC_FOLDER, filename)

# 数据库操作辅助函数
def execute_query(query, params=(), fetchone=False, many=False):
    conn = sqlite3.connect(LOCAL_DB_PATH)
    c = conn.cursor()
    c.execute(query, params)
    
    if fetchone:
        result = c.fetchone()
    elif many:
        result = c.fetchall()
    else:
        conn.commit()
        result = None
        
    conn.close()
    return result

# 激活码操作（纯本地）
def add_codes(codes):
    for code in codes:
        execute_query('INSERT OR IGNORE INTO codes (code) VALUES (?)', (code,))
    return True

def get_all_codes():
    return execute_query('SELECT code, used FROM codes', many=True)

def validate_code_db(code):
    result = execute_query('SELECT used FROM codes WHERE code = ?', (code,), fetchone=True)
    if result and not result[0]:
        execute_query('UPDATE codes SET used = 1 WHERE code = ?', (code,))
        return True
    return False

def disable_code_db(code):
    execute_query('UPDATE codes SET used = 1 WHERE code = ?', (code,))

# API路由
@app.route('/api/validate-code', methods=['POST'])
def validate_code():
    data = request.get_json()
    code = data.get('code')
    if not code:
        return jsonify({'success': False, 'message': '请提供激活码'})
    
    if validate_code_db(code):
        return jsonify({'success': True, 'message': '激活码验证成功'})
    return jsonify({'success': False, 'message': '无效的激活码或已被使用'})

@app.route('/api/generate-codes', methods=['POST'])
def generate_codes():
    data = request.get_json()
    count = data.get('count', 1)
    if not isinstance(count, int) or count < 1:
        return jsonify({'success': False, 'message': '无效的数量'})
    
    codes = [''.join(random.choices(string.ascii_uppercase + string.digits, k=8)) for _ in range(count)]
    if add_codes(codes):
        return jsonify({'success': True, 'codes': codes, 'count': len(codes)})
    return jsonify({'success': False, 'message': '生成失败'})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    activation_code = data.get('activationCode')
    
    if not all([username, password, activation_code]):
        return jsonify({'success': False, 'message': '请填写所有必填项'})
    
    # 验证激活码
    if not validate_code_db(activation_code):
        return jsonify({'success': False, 'message': '无效的激活码或已被使用'})
    
    # 检查用户名是否已存在
    if execute_query('SELECT 1 FROM users WHERE username = ?', (username,), fetchone=True):
        return jsonify({'success': False, 'message': '用户名已存在'})
    
    # 存储用户信息
    execute_query('INSERT INTO users (username, password) VALUES (?, ?)', 
                 (username, password))
    
    return jsonify({'success': True, 'message': '注册成功'})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not all([username, password]):
        return jsonify({'success': False, 'message': '请填写用户名和密码'})
    
    user = execute_query('SELECT password FROM users WHERE username = ?', 
                        (username,), fetchone=True)
    
    if user and user[0] == password:
        return jsonify({'success': True, 'message': '登录成功', 'username': username})
    
    return jsonify({'success': False, 'message': '用户名或密码错误'})

# 管理员功能
@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    try:
        username = request.json.get('username')
        password = request.json.get('password')

        row = execute_query(
            "SELECT password FROM users WHERE username = ? AND is_admin = 1",
            (username,), fetchone=True
        )

        if not row or row[0] != password:
            return jsonify({'error': '用户名或密码错误'}), 401
        return jsonify({'message': '管理员登录成功'})
    except Exception as e:
        print(f"管理员登录错误: {str(e)}")
        return jsonify({'error': '登录失败'}), 500

@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    try:
        users = execute_query("SELECT id, username, is_admin, created_at FROM users")
        return jsonify({'users': [{
            'id': row[0],
            'username': row[1],
            'is_admin': bool(row[2]),
            'created_at': row[3]
        } for row in users]})
    except Exception as e:
        print(f"获取用户列表错误: {str(e)}")
        return jsonify({'error': '获取用户列表失败'}), 500

@app.route('/api/admin/codes', methods=['GET'])
def admin_get_codes():
    try:
        codes = execute_query("SELECT code, used, created_at FROM codes")
        return jsonify({'codes': [{
            'code': row[0],
            'used': bool(row[1]),
            'created_at': row[2]
        } for row in codes]})
    except Exception as e:
        print(f"获取激活码错误: {str(e)}")
        return jsonify({'error': '获取激活码失败'}), 500

@app.route('/api/get-codes', methods=['GET'])
def get_codes():
    codes = get_all_codes()
    code_list = [{'code': c[0], 'used': bool(c[1])} for c in codes]
    return jsonify({'codes': code_list})

@app.route('/api/disable-code', methods=['POST'])
def disable_code():
    data = request.get_json() if request.is_json else request.form
    code = data.get('code')
    if not code:
        return jsonify({'success': False, 'message': '请提供激活码'})
    disable_code_db(code)
    return jsonify({'success': True, 'message': f'激活码 {code} 已禁用'})


# 删除单个激活码
@app.route('/api/delete-code', methods=['POST'])
def delete_code_api():
    data = request.get_json() if request.is_json else request.form
    code = data.get('code')
    if not code:
        return jsonify({'success': False, 'message': '请提供激活码'}), 400
    execute_query('DELETE FROM codes WHERE code = ?', (code,))
    return jsonify({'success': True, 'message': f'激活码 {code} 已删除'})

# 一键删除所有激活码
@app.route('/api/delete-all-codes', methods=['POST'])
def delete_all_codes():
    execute_query('DELETE FROM codes')
    return jsonify({'success': True, 'message': '所有激活码已删除'})

# 支持访问 navpages 下的 html 页面
@app.route('/navpages/<path:filename>')
def navpages_files(filename):
    return send_from_directory('navpages', filename)

# 支持访问 card 下的 html 页面
@app.route('/card/<path:filename>')
def card_files(filename):
    return send_from_directory('card', filename)


# AI 问答接口
import os
import requests as ext_requests  # 需确保已安装 requests 库（pip install requests）

@app.route('/api/ai-chat', methods=['POST'])
def ai_chat():
    try:
        data = request.get_json()
        user_message = data.get('message')
        if not user_message:
            return jsonify({'success': False, 'message': '请输入问题'}), 400

        api_key = os.environ.get('OPENROUTER_API_KEY')
        if not api_key:
            return jsonify({'success': False, 'message': '未配置AI接口密钥'}), 500

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            # 可选：可加站点信息
            #'HTTP-Referer': request.host_url,
            #'X-Title': 'EnglishQuestion',
        }
        payload = {
            'model': 'deepseek/deepseek-chat-v3-0324:free',
            'messages': [
                {'role': 'user', 'content': user_message}
            ]
        }
        resp = ext_requests.post(
            url='https://openrouter.ai/api/v1/chat/completions',
            headers=headers,
            data=json.dumps(payload),
            timeout=30
        )
        if resp.status_code != 200:
            return jsonify({'success': False, 'message': 'AI接口请求失败', 'detail': resp.text}), 502
        result = resp.json()
        # 兼容 OpenRouter 返回格式
        ai_reply = ''
        if 'choices' in result and result['choices']:
            ai_reply = result['choices'][0]['message']['content']
        else:
            ai_reply = result.get('message', 'AI无回复')
        return jsonify({'success': True, 'reply': ai_reply})
    except Exception as e:
        return jsonify({'success': False, 'message': 'AI接口异常', 'detail': str(e)}), 500



if __name__ == '__main__':
    app.run(debug=True)
