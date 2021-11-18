from flask import Flask, render_template,abort, redirect, url_for, flash,session,g,request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm,RegisterForm,LoginForm,CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
import os
Base = declarative_base()

login_manager = LoginManager()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

ckeditor = CKEditor(app)
Bootstrap(app)
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE1_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id=db.Column(db.Integer,ForeignKey('user.id'))
    comments = relationship("Comment", back_populates="parent_post")

class User(UserMixin,db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password=db.Column(db.String(120),nullable=False)
    posts=relationship('BlogPost',back_populates="author")
    comments=relationship('Comment',back_populates="comment_author")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


db.create_all()

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)

@app.route('/register',methods=['GET','POST'])
def register():
    register_form=RegisterForm()
    login_form = LoginForm()
    if register_form.validate_on_submit():
        name=register_form.name.data
        email=register_form.email.data
        password=register_form.password.data
        check_user = User.query.filter_by(email=email).first()
        if check_user:
            flash('You have already an account with us')
            return redirect(url_for('login'))
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256',
                                                                       salt_length=8)
            newuser = User(email=email, name=name, password=hashed_password)
            db.session.add(newuser)
            db.session.commit()
            # Log in and authenticate user after adding details to database.
            login_user(newuser)
            flash(f'Successfully registered : {name}' )
            return redirect(url_for('get_all_posts'))
    return render_template("register.html",form=register_form)


@app.route('/login',methods=['GET','POST'])
def login():
    login_form=LoginForm()
    if login_form.validate_on_submit():
        email=login_form.email.data
        plain_password=login_form.password.data
        logged_user = User.query.filter_by(email=email).first()

        if logged_user:
            hashed_pword=logged_user.password
            if check_password_hash(pwhash=hashed_pword, password=plain_password):
                login_user(logged_user)
                flash(f'Logged in successfully: {logged_user.name}')
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password Error Not authorised')
                return redirect(url_for('login'))
        else:
            flash('No user registered')
            return redirect(url_for('login'))

    return render_template("login.html",form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=['GET','POST'])
def show_post(post_id):
    commentform=CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if commentform.validate_on_submit():
        if current_user.is_authenticated:
            newcomments=Comment(
                post_id=requested_post.id,
                author_id=current_user.id,
                text=commentform.body.data
            )
            db.session.add(newcomments)
            db.session.commit()
            return redirect(url_for('get_all_posts'))
        else:

            flash("You are not authorised to post comments. Login please")
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post,form=commentform, logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html",logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['GET','POST'])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET','POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, logged_in=current_user.is_authenticated))

    return render_template("make-post.html", form=edit_form , logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='192.168.0.111', port=5000, debug=True)
