from flask_app import app
from flask import render_template,redirect,request,session,flash
from flask_app.models.user import User

from flask_app import app
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)


@app.route('/')
def index():
    return render_template('index.html')


@app.route("/register", methods=["POST"])
def register():

    # validate user
    print(request.form)
    is_valid = User.validate_register(request.form)
    if not is_valid:
        return redirect("/")
    else:

        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        print(pw_hash)

        data = {
            "first_name": request.form['first_name'],
            "last_name": request.form['last_name'],
            "email": request.form['email'],
            "password" : pw_hash
        }

        user_id = User.save(data)
        
        session['user_id'] = user_id
        return redirect("/dashboard")




@app.route('/dashboard')
def main():
    user_id = session['user_id']

    data = {
        "user_id" : session['user_id']
    }

    user = User.get_user_info(data)

    return render_template('dashboard.html', user = user)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/login", methods=['POST'])
def login():
    data = { 
        "email" : request.form["email"]
        }
    user_in_db = User.get_by_email(data)
    
    if not user_in_db:
        flash("Invalid Email/Password")
        return redirect("/")

    if not bcrypt.check_password_hash(user_in_db.password, request.form['password']):
        
        flash("Invalid Email/Password")
        return redirect('/')
        
    session['user_id'] = user_in_db.id

    return redirect("/dashboard")
