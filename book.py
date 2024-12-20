# -*- coding: utf-8 -*-
import base64
from sqlite3 import dbapi2 as sqlite3
from hashlib import md5
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
    render_template, abort, g, flash, _app_ctx_stack
from werkzeug.security import check_password_hash, generate_password_hash
import time

#CONFIGURATION
DATABASE = 'book.db'
DEBUG = True
SECRET_KEY = 'development key'
MANAGER_NAME = 'root'
MANAGER_PWD = 'root'
app = Flask(__name__)
app.config['DEBUG'] = True
app.config.from_object(__name__)
app.config.from_envvar('FLASKR_SETTINGS', silent=True)


def get_db():
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        top.sqlite_db.row_factory = sqlite3.Row
    return top.sqlite_db


@app.teardown_appcontext
def close_database(exception):
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db'):
        top.sqlite_db.close()


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('book.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
    rv = query_db('select user_id from users where user_name = ?',
                  [username], one=True)
    return rv[0] if rv else None


def get_recommendations():
    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute('SELECT DISTINCT book_id FROM borrows')
        book_ids = cursor.fetchall()
        print(f"Book IDs: {book_ids}")  # 调试信息

        recommendations = []
        for book_id in book_ids:
            cursor.execute('SELECT book_id, book_name, data FROM books WHERE book_id = ?', (book_id['book_id'],))
            book_info = cursor.fetchone()

            if book_info:
                print(f"Book info: {book_info}")  # 调试信息

                image_data = base64.b64encode(book_info['data']).decode('utf-8')
                recommendations.append({
                    'id': book_info['book_id'],
                    'book_name': book_info['book_name'],
                    'image_data': image_data
                })

        return recommendations

    except sqlite3.Error as e:
        print("Database error:", e)
        return []
    finally:
        cursor.close()

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = session['user_id']


@app.route('/')
def index():
    # 获取推荐图书信息
    books_p = get_recommendations()
    return render_template('index.html', books_p=books_p)



@app.route('/manager_login', methods=['GET', 'POST'])
def manager_login():
    error = None
    if request.method == 'POST':
        manager = query_db('''select * from manager_info where manager_id = ?''',
                           [request.form['user_id']], one=True)
        if manager is None:
            error = 'Invalid username'
        elif not check_password_hash(manager['password'], request.form['password']):
            error = 'Invalid password'
        else:
            session['user_id'] = app.config['MANAGER_NAME']
            return redirect(url_for('manager'))
    return render_template('manager_login.html', error=error)


@app.route('/reader_login', methods=['GET', 'POST'])
def reader_login():
    error = None
    if request.method == 'POST':
        user = query_db('''select * from users where user_name = ?''',
                        [request.form['username']], one=True)
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pwd'], request.form['password']):
            error = 'Invalid password'
        else:
            session['user_id'] = user['user_name']
            return redirect(url_for('reader'))
    return render_template('reader_login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            db = get_db()
            db.execute('''insert into users (user_name, pwd, college, num, email)
   values (?, ?, ?, ?, ?) ''', [request.form['username'], generate_password_hash(
                request.form['password']), request.form['college'], request.form['number'],
                                request.form['email']])
            db.commit()
            return redirect(url_for('reader_login'))
    return render_template('register.html', error=error)


from flask import Flask, request, jsonify


@app.route('/recommend_books', methods=['POST'])


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))


# 添加简单的安全性检查
def manager_judge():
    if not session.get('user_id'):
        error = 'Invalid manager, please login'
        return render_template('manager_login.html', error=error)
    else:
        return None


def reader_judge():
    if not session['user_id']:
        error = 'Invalid reader, please login'
        return render_template('reader_login.html', error=error)


@app.route('/manager/books')
def manager_books():
    manager_judge()
    return render_template('manager_books.html',
                           books=query_db('select * from books', []))


@app.route('/manager')
def manager():
    manager_judge()
    return render_template('manager.html')


@app.route('/reader')
def reader():
    reader_judge()
    return render_template('reader.html')


@app.route('/manager/users')
def manager_users():
    manager_judge()
    users = query_db('''select * from users''', [])
    return render_template('manager_users.html', users=users)


@app.route('/manager/user/modify/<id>', methods=['GET', 'POST'])
def manger_user_modify(id):
    # user_judge()
    error = None
    user = query_db('''select * from users where user_id = ?''', [id], one=True)
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to input your name'
        elif not request.form['password']:
            db = get_db()
            db.execute('''update users set user_name=?, college=?, num=? \
				, email=? where user_id=? ''', [request.form['username'],
                                                request.form['college'], request.form['number'],
                                                request.form['email'], id])
            db.commit()
            return redirect(url_for('manager_user', id=id))
        else:
            db = get_db()
            db.execute('''update users
set user_name=?
  , pwd=?
  , college=?
  , num=?
  , email=?
where user_id = ? ''', [request.form['username'],
                        generate_password_hash(request.form['password']),
                        request.form['college'], request.form['number'],
                        request.form['email'], id])
            db.commit()
            return redirect(url_for('manager_user', id=id))
    return render_template('manager_user_modify.html', user=user, error=error)


@app.route('/manager/user/deleter/<id>', methods=['GET', 'POST'])
def manger_user_delete(id):
    manager_judge()
    db = get_db()
    db.execute('''delete from users where user_id=? ''', [id])
    db.commit()
    return redirect(url_for('manager_users'))


@app.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    error = None
    if request.method == 'POST':
        if not request.form.get('password'):
            error = 'You have to input your password'
        # 检查 manager_id 是否存在
        elif not request.form.get('manager_id'):
            error = 'You have to input your manager_id'
        else:
            # 获取表单数据
            password = request.form['password']
            manager_id = request.form['manager_id']

            # 连接数据库
            db = get_db()

            # 插入数据到数据库
            db.execute('''
                    INSERT INTO manager_info (manager_id, password)
                    VALUES (?, ?)
                ''', (manager_id, generate_password_hash(password)))
            db.commit()
            flash('Registration successful!', 'success')
        return redirect(url_for('manager_login'))
    return render_template('register_admin.html', error=error)


@app.route('/manager/books/add', methods=['GET', 'POST'])
def manager_books_add():
    manager_judge()
    error = None
    if request.method == 'POST':
        if not request.form['id']:
            error = 'You have to input the book ISBN'
        elif not request.form['name']:
            error = 'You have to input the book name'
        elif not request.form['author']:
            error = 'You have to input the book author'
        elif not request.form['company']:
            error = 'You have to input the publish company'
        elif not request.form['date']:
            error = 'You have to input the publish date'
        else:
            db = get_db()
            db.execute('''insert into books (book_id, book_name, author, publish_com,
				publish_date) values (?, ?, ?, ?, ?) ''', [request.form['id'],
                                                           request.form['name'], request.form['author'],
                                                           request.form['company'],
                                                           request.form['date']])
            db.commit()
            return redirect(url_for('manager_books'))
    return render_template('manager_books_add.html', error=error)


@app.route('/manager/books/delete', methods=['GET', 'POST'])
def manager_books_delete():
    manager_judge()
    error = None
    if request.method == 'POST':
        if not request.form['id']:
            error = 'You have to input the book name'
        else:
            book = query_db('''select * from books where book_id = ?''',
                            [request.form['id']], one=True)
            if book is None:
                error = 'Invalid book id'
            else:
                db = get_db()
                db.execute('''delete from books where book_id=? ''', [request.form['id']])
                db.commit()
                return redirect(url_for('manager_books'))
    return render_template('manager_books_delete.html', error=error)


@app.route('/manager/book/<id>', methods=['GET', 'POST'])
def manager_book(id):
    manager_judge()
    book = query_db('''select * from books where book_id = ?''', [id], one=True)
    reader = query_db('''select * from borrows where book_id = ?''', [id], one=True)
    name = query_db('''select user_name from borrows where book_id = ?''', [id], one=True)

    current_time = time.strftime('%Y-%m-%d', time.localtime(time.time()))
    if request.method == 'POST':
        db = get_db()
        db.execute('''update histroys set status = ?, date_return = ?  where book_id=?
			and user_name=? and status=? ''',
                   ['retruned', current_time, id, name[0], 'not return'])
        db.execute('''delete from borrows where book_id = ? ''', [id])
        db.commit()
        return redirect(url_for('manager_book', id=id))

    return render_template('manager_book.html', book=book, reader=reader)


@app.route('/manager/user/<id>', methods=['GET', 'POST'])
def manager_user(id):
    manager_judge()
    user = query_db('''select * from users where user_id = ?''', [id], one=True)
    books = None
    return render_template('manager_userinfo.html', user=user, books=books)


@app.route('/manager/modify/<id>', methods=['GET', 'POST'])
def manager_modify(id):
    manager_judge()
    error = None
    book = query_db('''select * from books where book_id = ?''', [id], one=True)
    if request.method == 'POST':
        if not request.form['name']:
            error = 'You have to input the book name'
        elif not request.form['author']:
            error = 'You have to input the book author'
        elif not request.form['company']:
            error = 'You have to input the publish company'
        elif not request.form['date']:
            error = 'You have to input the publish date'
        else:
            db = get_db()
            db.execute('''update books set book_name=?, author=?, publish_com=?, publish_date=? where book_id=? ''',
                       [request.form['name'], request.form['author'], request.form['company'], request.form['date'],
                        id])
            db.commit()
            return redirect(url_for('manager_book', id=id))
    return render_template('manager_modify.html', book=book, error=error)


@app.route('/reader/info', methods=['GET', 'POST'])
def reader_info():
    reader_judge()
    user = query_db('''select * from users where user_name=? ''', [g.user], one=True)
    return render_template('reader_info.html', user=user)


@app.route('/reader/modify', methods=['GET', 'POST'])
def reader_modify():
    reader_judge()
    error = None
    user = query_db('''select * from users where user_name = ?''', [g.user], one=True)
    id = user[0]
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to input your name'
        elif not request.form['password']:
            db = get_db()
            db.execute('''update users set user_name=?, college=?, num=? \
				, email=? where user_id=? ''', [request.form['username'],
                                                request.form['college'], request.form['number'],
                                                request.form['email'], id])
            db.commit()
            return redirect(url_for('reader_info'))
        else:
            db = get_db()
            db.execute('''update users set user_name=?, pwd=?, college=?, num=? \
				, email=? where user_id=? ''', [request.form['username'],
                                                generate_password_hash(request.form['password']),
                                                request.form['college'], request.form['number'],
                                                request.form['email'], id])
            db.commit()
            return redirect(url_for('reader_info'))
    return render_template('reader_modify.html', user=user, error=error)


def reader_want():
    reader_judge()


@app.route('/reader/query', methods=['GET', 'POST'])
def reader_query():
    reader_judge()
    error = None
    books = None
    if request.method == 'POST':
        if request.form['item'] == 'name':
            if not request.form['query']:
                error = 'You have to input the book name'
            else:
                books = query_db('''select * from books where book_name = ?''',
                                 [request.form['query']])
                if not books:
                    error = 'Invalid book name'
        else:
            if not request.form['query']:
                error = 'You have to input the book author'
            else:
                books = query_db('''select * from books where author = ?''',
                                 [request.form['query']])
                if not books:
                    error = 'Invalid book author'
    return render_template('reader_query.html', books=books, error=error)


@app.route('/reader/book/<id>', methods=['GET', 'POST'])
def reader_book(id):
    reader_judge()
    error = None
    book = query_db('''select * from books where book_id = ?''', [id], one=True)
    reader = query_db('''select * from borrows where book_id = ?''', [id], one=True)
    count = query_db('''select count(book_id) from borrows where user_name = ? ''',
                     [g.user], one=True)

    current_time = time.strftime('%Y-%m-%d', time.localtime(time.time()))
    return_time = time.strftime('%Y-%m-%d', time.localtime(time.time() + 2600000))
    if request.method == 'POST':
        if reader:
            error = 'The book has already borrowed.'
        else:
            if count[0] == 3:
                error = 'You can\'t borrow more than three books.'
            else:
                db = get_db()
                db.execute('''insert into borrows (user_name, book_id, date_borrow, 
					date_return) values (?, ?, ?, ?) ''', [g.user, id,
                                                           current_time, return_time])
                db.execute('''insert into histroys (user_name, book_id, date_borrow, 
					status) values (?, ?, ?, ?) ''', [g.user, id,
                                                      current_time, 'not return'])
                db.commit()
                return redirect(url_for('reader_book', id=id))
    return render_template('reader_book.html', book=book, reader=reader, error=error)


@app.route('/reader/histroy', methods=['GET', 'POST'])
def reader_histroy():
    reader_judge()
    histroys = query_db(
        '''select * from histroys, books where histroys.book_id = books.book_id and histroys.user_name=? ''', [g.user],
        one=False)

    return render_template('reader_histroy.html', histroys=histroys)


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
