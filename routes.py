'''
Joshua Carnahan | SDEV 300 6380 | Lab 8
This app is a continuation of the previous web page made in lab 7.
this updated version of the web app now includes an update password function
the way my page will work is you will enter your username and password
the program will verify those match and you also enter the new pw
the program will rewrite the database.txt file with all original info
and new pw. the pw criteria is now also updated to where if the user
enters a password that is considered too common in the CommonPassword.txt
file it will not accept the password and prompt the user to enter a 
more complex pw. there is also an additional file called attempts.log
this file will log every unsuccesful attempt to login to a user.
'''

import re
import secrets
import os
from datetime import date, datetime
from flask import Flask
from flask import render_template
from flask import redirect
from flask import url_for
from flask import request
from flask import session
from passlib.hash import sha256_crypt

app = Flask(__name__)

app.config['SECRET_KEY'] = secrets.token_urlsafe(16)

def check_common(password):
    ''' this function will cross check a password with the commonpassword.txt file '''
    with open("CommonPassword.txt","r", encoding="utf8") as file:
        for each_password in file:
            if each_password.strip() in password:
                return False
    return True

def validate_password(password):
    """this function validates the password complexity/length requirements"""
    reg = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{12,}$"
    pattern = re.compile(reg)
    match = re.search(pattern, password)
    # if the password meets requirements
    if match:
        return True

    return False

def ensure_file_exists(file):
    """this function ensure the database.text file exists. If not it creates it"""
    if not os.path.isfile(file):
        with open(file, "a", encoding='utf-8') as _file:
            print(f"File open/created: {file}")

def unique_username(user):
    """this function ensures that the username provided at registration is unique"""
    # make sure database.text exists
    ensure_file_exists("database.txt")
    # open database
    with open("database.txt", "r", encoding='utf-8') as file:
        # read database and store
        data = file.readlines()

    data = [x.split() for x in data]
    # iterate through data and check usernames
    for item in data:
        if item[0].strip() == user:
            return False

    return True

# two decorators, same function
@app.route('/login', methods=['GET', 'POST'])
def login():
    '''
    This is the function that will take the user to the login page first
    '''
    if request.method == 'POST':
        # ensure database exists
        ensure_file_exists("database.txt")
        # open file
        with open("database.txt", "r", encoding='utf-8') as file:
            # read file and store in data variable
            data = file.readlines()
        # get username and password from form and store in variables
        username = request.form['username']
        password = request.form['password']
        data = [x.split() for x in data]
        # if there is not data
        if not data:
            # send the user to the registration screen
            message = "No users exist. Please register."
            return render_template("register.html", error=message,
                                   datetime=str(datetime.now()),
                                   the_title='Platypus Registration')
        # else iterate through the database and check if credentials exist
        for item in data:
            print(f"Working on item: {item}")
            if username == item[0].strip() and \
                    sha256_crypt.verify(password, item[1].strip()):
                if not check_common(password):
                    message = "This password is common, please update password at "\
                    "bottom of page"
                session['logged-in'] = True
                return redirect(url_for('main'))

        # if the username/pass if invalid then print message and render login page
        message = "Invalid username and/or password."

        # write a failed login attempts to a log file
        with open("attempts.log", "a", encoding='utf-8') as logs:
            date_at= str(date.today())
            time_at =  str(datetime.now())
            ip_address = request.environ['REMOTE_ADDR']
            attempt = f"[{date_at}, {time_at}] {ip_address}\n"
            logs.write(attempt)

        return render_template('login.html', error=message,
                            datetime=str(datetime.now()), the_title='Platypus Login')

    # else render login page
    return render_template("login.html",
                           datetime=str(datetime.now()),
                           the_title='Platypus Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    '''
    This will take the user to a register page if they do not have an account
    '''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hash_pass = sha256_crypt.hash(password)
        page = "register.html"
        title = "Platypus Registration"

        # validate that username field has entry
        if not username:
            message = "Please enter a username."
        # validate that password field has entry
        elif not password:
            message = "Please enter a password."
        # validate that username is unique
        elif not unique_username(username):
            message = "Username is already registered."
        # validate password complexity and length
        elif not validate_password(password):
            message = "Password must include at least 12 characters, "\
            "at least 1 uppercase character, 1 lowercase character, "\
            "1 number and 1 special character."
        # validate password with PasswordCommon.txt
        elif not check_common(password):
            message = "This is a common password, "\
                    "please make a more complex password."
        # if all validation passes then register user
        else:
            with open("database.txt", "a", encoding='utf-8') as file:
                file.write(f"{username} {hash_pass}\n")
            message = "Successfully registered!"
            page = "login.html"
            title = "Platypus Login"

        # render the specified page, message and page title
        return render_template(page, error=message,
                               datetime=str(datetime.now()),
                               the_title=title)
    return render_template('register.html', datetime=str(datetime.now()),
                         the_title='Platypus Registration')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """this function handles the logout functionality for the webpage"""
    # if logged in then log out
    if 'logged-in' in session:
        session.pop('logged-in')
    message = "Logged out successfully"
    return render_template("login.html", error=message,
                           datetime=str(datetime.now()),
                           the_title='Platypus Login')

@app.route('/update', methods=['GET', 'POST'])
def update():
    ''' This is the route for password updating '''
    if 'logged-in' not in session:
        return redirect(url_for('login'))
    # open file
    with open("database.txt", "r+", encoding='utf-8') as file:
        # read file
        data = file.readlines()

    message = "Password must include at least 12 characters,"\
            "at least 1 uppercase character, 1 lowercase character, "\
            "1 number and 1 special character."

    if request.method == 'POST':
        # get username and password
        username = request.form['username']
        password = request.form['password']
        new_password = request.form['new password']
        data = [x.split() for x in data]
        hash_pass = sha256_crypt.hash(new_password)
        page = "passUpdate.html"
        title = "Update Password"

        # else iterate through the database and check if credentials exist
        for item in data:
            print(f"Working on item: {item}")
            if username == item[0].strip() and \
                    sha256_crypt.verify(password, item[1].strip()):
                # validate password complexity and length
                if not validate_password(new_password):
                    message = "Password must include at least 12 characters, "\
                            "at least 1 uppercase character, 1 lowercase character, "\
                            "1 number and 1 special character."
                # crosscheck with CommonPassword.txt
                elif not check_common(new_password):
                    message = "This is a common password, "\
                            "please make a more complex password."
                # if all validation passes then register user
                else:
                    # reassign current item with new password
                    item[1] = hash_pass
                    # clear database.txt with lines read and stored to data
                    open("database.txt", "w", encoding='utf-8').close()
                    # rewrite all data with the new password
                    with open("database.txt", "a", encoding='utf-8') as file:
                        for i in data:
                            file.write(f"{i[0]} {i[1]}\n")
                    if 'logged-in' in session:
                        session.pop('logged-in')
                    message = "Successfully updated password!"
                    page = "login.html"
                    title = "Platypus Login"
            else:
                # if the username/pass if invalid then print message and render login page
                message = "Invalid username and/or password."

        # render the specified page, message and page title
        return render_template(page, error=message,
                               datetime=str(datetime.now()),
                               the_title=title)

    return render_template('passUpdate.html', error=message,
                            datetime=str(datetime.now()),
                            the_title='Update Password')


@app.route('/')
@app.route('/main')
def main():
    ''' this is where we cann on our main file page
    and render the html template with these two routes '''
    if 'logged-in' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', datetime=str(datetime.now()),
                            the_title='Platypus Home Page')

@app.route('/lifecycle')
def lifecycle():
    ''' when the lifecycle route is called this function
    will declare a new title and render the html file '''
    if 'logged-in' not in session:
        return redirect(url_for('login'))
    return render_template('lifecycle.html', datetime=str(datetime.now()),
                            the_title='Platypus Life')

@app.route('/venom')
def venom():
    ''' when venom route is called this function will
    declare a new title and render the venom html file '''
    if 'logged-in' not in session:
        return redirect(url_for('login'))
    return render_template('venom.html', datetime=str(datetime.now()),
                            the_title='Platypus Poison, Form and Function')

@app.route('/history')
def history():
    ''' when history route is called this function will
        declare a new title and render the history html file '''
    if 'logged-in' not in session:
        return redirect(url_for('login'))
    return render_template('history.html', datetime=str(datetime.now()),
                            the_title='Natural history')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
