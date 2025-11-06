from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap 
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField 
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError 
from flask_sqlalchemy import SQLAlchemy 
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user 
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_mail import Mail, Message 
from itsdangerous import URLSafeTimedSerializer as Serializer
from threading import Thread
from datetime import datetime
from flask_moment import Moment
from config import Config
from hashlib import md5
from flask_pagedown import PageDown 
from markdown import markdown
import bleach 
from sqlalchemy.event import listen 
from sqlalchemy import Table, Column, Integer, ForeignKey, DateTime 
from functools import wraps 

# --- 1. HÀM GỬI EMAIL ---
def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            print(f"LỖI GỬI MAIL: {e}")

def send_email(to, subject, template, **kwargs):
    msg = Message(
        app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + ' ' + subject,
        sender=app.config['FLASKY_MAIL_SENDER'],
        recipients=[to]
    )
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr


# --- 2. KHỞI TẠO CÁC EXTENSIONS ---
app = Flask(__name__)
app.config.from_object(Config)
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
moment = Moment(app) 
pagedown = PageDown(app) 
login_manager.login_view = 'login' 
login_manager.login_message = 'Vui lòng đăng nhập để xem trang này.'

# --- BỔ SUNG: CONTEXT PROCESSOR ĐỂ ĐƯA PERMISSION VÀO TEMPLATE ---
@app.context_processor
def inject_permissions():
    """Làm cho class Permission có sẵn trong tất cả các template."""
    return dict(Permission=Permission)


# --- 3. MODELS ---

# HẰNG SỐ PERMISSIONS (QUYỀN)
class Permission:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8     
    ADMIN = 16

# Bảng liên kết (Association Table) cho mối quan hệ "Follow"
follows = db.Table('follows',
    db.Column('follower_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('followed_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('timestamp', db.DateTime, default=datetime.utcnow)
)

# MODEL ROLE
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    @staticmethod
    def insert_roles():
        roles = {
            'User': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE],
            'Moderator': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE, Permission.MODERATE],
            'Administrator': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE,
                              Permission.MODERATE, Permission.ADMIN]
        }
        default_role = 'User'
        for r, perms in roles.items():
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in perms:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def reset_permissions(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm


# MODEL USER (ĐÃ HỢP NHẤT)
class User(UserMixin, db.Model):
    __tablename__ = 'users' 
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), index=True, unique=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(256))
    confirmed = db.Column(db.Boolean, default=False)
    
    # THUỘC TÍNH ROLE
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id')) 
    
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    
    profile = db.relationship('Profile', back_populates='user', uselist=False)
    posts = db.relationship('Post', backref='author', lazy='dynamic') 

    # MỐI QUAN HỆ FOLLOWS
    followed = db.relationship(
        'User', secondary=follows,
        primaryjoin=(follows.c.follower_id == id),
        secondaryjoin=(follows.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), 
        lazy='dynamic')

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == app.config.get('FLASKY_ADMIN_EMAIL'): 
                self.role = Role.query.filter_by(name='Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

    # PHƯƠNG THỨC KIỂM TRA QUYỀN
    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    @property
    def is_administrator(self):
        return self.can(Permission.ADMIN)
        
    @property
    def can_comment(self):
        return self.can(Permission.COMMENT)
        
    # PHƯƠNG THỨC BẢO MẬT & FOLLOW & GRAVATAR
    def set_password(self):
        self.password_hash = generate_password_hash(self.password_hash)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self):
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'confirm': self.id}) 

    def confirm(self, token, expiration=3600):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=expiration)
        except Exception:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True
        
    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
        db.session.commit()

    def gravatar(self, size=40, default='identicon', rating='g'):
        hash_value = md5(self.email.lower().encode('utf-8')).hexdigest()
        return (f'https://secure.gravatar.com/avatar/{hash_value}?'
                f's={size}&d={default}&r={rating}')
                
    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        if user.id is None:
            return False
        return self.followed.filter(
            follows.c.followed_id == user.id).count() > 0

    def is_followed_by(self, user):
        if user.id is None:
            return False
        return self.followers.filter(
            follows.c.follower_id == user.id).count() > 0
            
    def followed_posts(self):
        return Post.query.join(follows, (follows.c.followed_id == Post.user_id)).filter(
            follows.c.follower_id == self.id).order_by(Post.timestamp.desc()) 


class Profile(db.Model):
    __tablename__ = 'profiles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', back_populates='profile')


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text) 
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return f'<Post {self.id}>'
        
    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        """Tự động chuyển đổi Markdown sang HTML và lọc XSS."""
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'p', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'img', 'br']
        
        html = markdown(value, extensions=['fenced_code'])
        
        target.body_html = bleach.linkify(bleach.clean(
            html, tags=allowed_tags, strip=True))

listen(Post.body, 'set', Post.on_changed_body)


# MODEL MỚI: COMMENT
class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean, default=False) 

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship('User', backref=db.backref('comments', lazy='dynamic'))

    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    post = db.relationship('Post', backref=db.backref('comments', lazy='dynamic'))

    def __repr__(self):
        return f'<Comment {self.id}>'


# --- user_loader (CẦN CHO FLASK-LOGIN) ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id)) 


# --- 4. FORMS ---
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('password2', message='Mật khẩu phải trùng khớp.')])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Register')

class EditProfileForm(FlaskForm):
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

class PostForm(FlaskForm):
    body = TextAreaField("What's on your mind?", validators=[DataRequired()]) 
    submit = SubmitField('Submit')

# FORM MỚI: COMMENT FORM
class CommentForm(FlaskForm):
    body = TextAreaField('Enter your comment', validators=[DataRequired()])
    submit = SubmitField('Submit')


# --- 5. HOOK ---
@app.before_request
def before_request_hook():
    if current_user.is_authenticated:
        current_user.ping() 

    if current_user.is_authenticated and not current_user.confirmed:
        endpoint = request.endpoint
        allowed_routes = ['login', 'register', 'unconfirmed', 'confirm', 'resend_confirmation', 'logout', 'static']
        if endpoint and endpoint not in allowed_routes:
            return redirect(url_for('unconfirmed'))


# --- 6. ROUTES ---

# Decorator Tùy chỉnh để kiểm tra quyền
def permission_required(permission):
    def decorator(f):
        @wraps(f) 
        @login_required
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ROUTE HOME 
@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
@app.route('/home/<int:page>', methods=['GET', 'POST']) 
@app.route('/home/show/<string:show>', methods=['GET', 'POST']) 
@app.route('/home/show/<string:show>/<int:page>', methods=['GET', 'POST']) 
@login_required 
def home(page=1, show='all'): 
    form = PostForm()
    if form.validate_on_submit():
        post = Post(body=form.body.data, author=current_user._get_current_object()) 
        db.session.add(post)
        db.session.commit()
        flash('Bài đăng đã được xuất bản!', 'success')
        return redirect(url_for('home', show=show, page=1)) 

    posts_per_page = app.config.get('FLASKY_POSTS_PER_PAGE', 20) 
    
    if show == 'followed' and current_user.is_authenticated:
        query = current_user.followed_posts()
    else:
        query = Post.query.order_by(Post.timestamp.desc())
        show = 'all'

    pagination = query.paginate(
        page=page, 
        per_page=posts_per_page,
        error_out=False
    )
    posts = pagination.items
    
    return render_template('home.html', 
                            title='Home', 
                            form=form, 
                            posts=posts, 
                            pagination=pagination,
                            show=show) 

# CẬP NHẬT ROUTE XEM BÀI ĐĂNG ĐƠN LẺ VÀ XỬ LÝ COMMENT
@app.route('/post/<int:id>', methods=['GET', 'POST']) 
@app.route('/post/<int:id>/<int:page>', methods=['GET', 'POST'])
@login_required
def post(id, page=1):
    post_obj = Post.query.get_or_404(id) 
    form = CommentForm() 

    if form.validate_on_submit():
        comment = Comment(
            body=form.body.data,
            post=post_obj,
            author=current_user._get_current_object() 
        )
        db.session.add(comment)
        db.session.commit()
        flash('Bình luận của bạn đã được đăng.', 'success')
        
        comments_per_page = app.config.get('FLASKY_COMMENTS_PER_PAGE', 10)
        page_num = (post_obj.comments.filter_by(disabled=False).count() - 1) // comments_per_page + 1 
        return redirect(url_for('post', id=post_obj.id, page=page_num, _anchor='comments'))

    comments_per_page = app.config.get('FLASKY_COMMENTS_PER_PAGE', 10) 

    # Logic mới: Chỉ hiển thị comment bị tắt cho chủ bài viết hoặc Admin
    query = post_obj.comments 
    if not (current_user.is_authenticated and (current_user == post_obj.author or current_user.is_administrator)):
        query = query.filter_by(disabled=False)

    pagination = query.order_by(Comment.timestamp.asc()).paginate(
        page=page,
        per_page=comments_per_page,
        error_out=False
    )
    comments = pagination.items
    
    return render_template('post.html', 
                           post=post_obj, 
                           title=f'Post {id}',
                           form=form,
                           comments=comments,
                           pagination=pagination)


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = Post.query.get_or_404(id)

    if current_user != post.author and not current_user.is_administrator:
        abort(403) 

    form = PostForm()
    
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        db.session.commit()
        flash('Bài đăng của bạn đã được cập nhật.', 'success')
        return redirect(url_for('post', id=post.id)) 

    form.body.data = post.body
    
    return render_template('edit_post.html', form=form, title='Edit Post')


@app.route('/user/<username>')
@login_required
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    
    posts = user.posts.order_by(Post.timestamp.desc()).limit(10).all()
    
    return render_template('user.html', 
                           user=user, 
                           title=user.username, 
                           posts=posts)
                           
@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Người dùng không tồn tại.', 'danger')
        return redirect(url_for('home'))
    if user == current_user:
        flash('Bạn không thể theo dõi chính mình!', 'warning')
        return redirect(url_for('user_profile', username=username))
    
    current_user.follow(user)
    db.session.commit()
    flash(f'Bạn đã theo dõi {username} thành công!', 'success')
    return redirect(url_for('user_profile', username=username))

@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Người dùng không tồn tại.', 'danger')
        return redirect(url_for('home'))
    if user == current_user:
        flash('Bạn không thể bỏ theo dõi chính mình!', 'warning')
        return redirect(url_for('user_profile', username=username))
    
    current_user.unfollow(user)
    db.session.commit()
    flash(f'Bạn đã bỏ theo dõi {username}.', 'info')
    return redirect(url_for('user_profile', username=username))


@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    
    if form.validate_on_submit():
        if current_user.profile is None:
            profile = Profile(user=current_user) 
            db.session.add(profile)
            db.session.commit()
        
        current_user.profile.name = form.name.data
        current_user.profile.location = form.location.data
        current_user.profile.about_me = form.about_me.data
        
        db.session.add(current_user.profile)
        db.session.commit()
        flash('Thông tin cá nhân của bạn đã được cập nhật.', 'success')
        
        return redirect(url_for('user_profile', username=current_user.username))

    if current_user.profile:
        form.name.data = current_user.profile.name
        form.location.data = current_user.profile.location
        form.about_me.data = current_user.profile.about_me
    
    return render_template('edit_profile.html', form=form, title='Edit Your Profile')


# ROUTE KIỂM DUYỆT (Dành cho chủ bài viết)
@app.route('/comment/disable/<int:id>')
@login_required
def disable_comment(id):
    comment = Comment.query.get_or_404(id)
    post_author = comment.post.author
    
    # Chỉ chủ bài viết hoặc Admin mới có quyền tắt
    if current_user == post_author or current_user.is_administrator:
        comment.disabled = True
        db.session.add(comment)
        db.session.commit()
        flash('Bình luận đã được tắt.', 'success')
    else:
        abort(403)
        
    return redirect(request.referrer or url_for('post', id=comment.post_id))


@app.route('/comment/enable/<int:id>')
@login_required
def enable_comment(id):
    comment = Comment.query.get_or_404(id)
    post_author = comment.post.author
    
    # Chỉ chủ bài viết hoặc Admin mới có quyền bật
    if current_user == post_author or current_user.is_administrator:
        comment.disabled = False
        db.session.add(comment)
        db.session.commit()
        flash('Bình luận đã được bật.', 'success')
    else:
        abort(403)
        
    return redirect(request.referrer or url_for('post', id=comment.post_id))


# --- 7. ROUTE XỬ LÝ LỖI ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', title='Not Found'), 404
    
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html', title='Forbidden'), 403


# --- 8. CÁC ROUTES XÁC THỰC ---
@app.route('/auth/login', methods=['GET', 'POST'])
def login(): 
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Email hoặc mật khẩu không đúng.', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        flash('Đăng nhập thành công.', 'success')
        next_page = request.args.get('next')
        return redirect(next_page or url_for('home'))
    return render_template('login.html', title='Login', form=form)

@app.route('/auth/logout')
@login_required
def logout():
    logout_user()
    flash('Bạn đã đăng xuất.', 'info')
    return redirect(url_for('login')) 

@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            email=form.email.data, 
            username=form.username.data,
            confirmed=False,
            password_hash=form.password.data 
        )

        user.set_password()
        db.session.add(user)
        
        # Cần commit user để lấy user.id trước khi gán role (nếu cần)
        # db.session.commit() 
        # (Tuy nhiên __init__ của User đã gán role mặc định)
        
        profile = Profile(user=user) 
        db.session.add(profile)
        
        db.session.commit()

        token = user.generate_confirmation_token()
        send_email(user.email, 
                   'Xác thực tài khoản của bạn', 
                   'mail/confirm', 
                   user=user, 
                   token=token)
        
        flash('Một email xác thực đã được gửi đến bạn.', 'info')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/auth/unconfirmed')
def unconfirmed():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if current_user.confirmed:
        return redirect(url_for('home'))
    return render_template('unconfirmed.html', title='Confirm your account')

@app.route('/auth/confirm/<token>')
@login_required 
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('home'))
    if current_user.confirm(token):
        db.session.commit()
        flash('Bạn đã xác thực tài khoản thành công!', 'success')
    else:
        flash('Link xác thực không hợp lệ hoặc đã hết hạn.', 'danger')
    return redirect(url_for('home'))

@app.route('/auth/resend')
@login_required
def resend_confirmation():
    if current_user.confirmed:
        return redirect(url_for('home'))
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 
               'Xác thực tài khoản của bạn', 
               'mail/confirm', 
               user=current_user, 
               token=token)
    flash('Một email xác thực mới đã được gửi đến bạn.', 'info')
    return redirect(url_for('unconfirmed'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
        Role.insert_roles() # <--- TẠO ROLES KHI KHỞI ĐỘNG
    app.run(debug=True, port=5000)