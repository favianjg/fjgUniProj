import os
import sys
import math
import uuid
from random import randint
from flask import Flask, render_template, redirect, url_for, send_file, request, session, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from mwm import db
from mwm.website.config.config import Config
from mwm.website.config.statistic_var import Statistics
from mwm.cuckooif.cuckooif import submit, is_done, get_cuckoo_status
from mwm.database.database import Ticket, User, Sample, VerificationLink, Task
from pathlib import Path
from re import match
from mwm.mailif.mailhandler import send_mail, replace_placeholder
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__, static_folder='static')

#CSRF Protection
csrf = CSRFProtect(app)
app.config.from_object(Config)

# Web-Security Sanierung
SELF = "'self'"
INLINE = "'unsafe-inline'"
csp = {
    'default-src':SELF,
    'style-src':[SELF,INLINE],
    'script-src':[SELF,INLINE],
    'img-src':[SELF,"data:"]
}
Talisman(app, force_https=False, content_security_policy=csp, session_cookie_secure=False)

# function to check for passwordpolicy
def checkpw(password):
    if (any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and len(password) >= 8 and len(password) <= 20):
        return True
    else:
        return False

#function to make Gigabyte out of Kilobyte
def to_gb(kb):
    return str(round(kb / 1024 / 1024, 2))


# function to send verification mail
def send_verification_mail(userId):
    # generate new link with type email, then load email texts
    link = db.add_verification_link(userId, 'email', str(uuid.uuid4().hex))
    htmlfile = open('website/templates/mailVerifikation.html', 'r', encoding="utf8")
    htmltext = htmlfile.read()
    htmlfile.close()
    mailfile = open('website/templates/mailVerifikation.txt', 'r', encoding="utf8")
    mailtext = mailfile.read()
    mailfile.close()

    # replace placeholders
    placeholders = {'LINK': 'http://malwaremuehle.dynip.online/nowVerify/' + db.get_model(VerificationLink, link).link}
    htmlmail = replace_placeholder(htmltext, placeholders)
    txtmail = replace_placeholder(mailtext, placeholders)
    # send mail
    send_mail(db.get_model(User, userId).email, 'Bitte verifiziere Deine E-Mail-Adresse', txtmail, htmlmail)

# route for the homepage
@app.route('/', methods=['GET', 'POST'])
def index():
    # A dictionary that translates the selected Operating System Value to the platform name used in cuckoo
    # TODO: Use the names that are used inside cuckoo
    osStringDict = {'0': 'notSelected', '1': 'cuckoo_Win7_Home_64bit_ma', '2': 'cuckoo_Win7_Prof_64b_ma',
                    '3': 'cuckoo_Win10_Home_64bit_ma',
                    '4': 'cuckoo_Win10_Pro_64bit_ma',
                    '5': 'cuckoo_Win10_Education_64bit_ma', '6': 'cuckoo_Win10_Pro_Education_64bit_ma',
                    # '7': 'cuckoo_Ubuntu_18.04_64bit_ma',
                    '7': 'cuckoo_Debian_64bit_ma',
                    '8': 'cuckoo_Debian_64bit_ma'}

    if request.method == 'GET':
        return render_template('index.html')

    if request.method == 'POST':
        # check if a URL analysis has been requested
        if 'url' in request.form:
            url = request.form['url']
            # getting the selected OS out of the form and translating it to the platform name used in cuckoo
            selectedOS = request.form['os2']
            if selectedOS == '0':
                return render_template('error.html', typeError=False, unknownTicket=False, noURL=False, noOS=True)
            else:
                # setting the platform option for the cuckoo submit function
                options = {'machine': osStringDict[selectedOS]}

                # submit to cuckoo
                cuckooticketID = submit([], url, options, user_id=session.get('logged_in'))
                if cuckooticketID:
                    return redirect(
                        url_for('analysisstarted', ticket=db.get_model(Ticket, cuckooticketID).ticket_val))
                else:
                    return render_template('error.html', typeError=False, unknownTicket=False, noURL=True,
                                           noOS=False)
        # check if the post request contains a file / a file analysis has been requested
        if 'file[0]' not in request.files:
            return redirect(request.url)
        file = request.files['file[0]']
        # if user did not select a file, or it has no name
        if file.filename == '':
            return redirect(request.url)
        if file:
            # sanitising filename
            filename = secure_filename(file.filename)
            # safe file inside the upload folder
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(path)
            # getting the selected OS out of the form and translating it to the platform name used in cuckoo
            selectedOS = request.form['os1']
            if selectedOS == '0':
                return render_template('error.html', typeError=False, unknownTicket=False, noURL=False, noOS=True)
            else:
                # setting the platform option for the cuckoo submit function
                options = {'machine': osStringDict[selectedOS]}
                # submit file to cuckoo
                cuckooticketID = submit(path, [], options, user_id=session.get('logged_in'))
                os.remove(path)
                if cuckooticketID:
                    return db.get_model(Ticket, cuckooticketID).ticket_val
                else:
                    return 'Error'


# route in case of nonexecuteable file submission
@app.route('/typeError')
def typeError():
    return render_template('error.html', typeError=True, unknownTicket=False, noURL=False, noOS=False)


# route that you visit after requesting a analysis on the homepage + it shows the ticket
@app.route('/analysisStarted/<string:ticket>')
def analysisstarted(ticket):
    return render_template('analysisStarted.html', ticket=ticket)


# route that normally shouldnt be visited - it tells you to first start a analysis on the homepage
@app.route('/analysisStarted/')
def analysisstartedWithoutParameter():
    return redirect(url_for('analysisstarted',
                            ticket='Ticket eingeben'))


# route to enter your ticket and get the report as pdf
@app.route('/enterTicket', methods=['GET', 'POST'])
def enterticket():
    if request.method == 'GET':
        return render_template('EnterTicket.html')
    if request.method == 'POST':
        if 'ticket' in request.form:
            return redirect(url_for('getReport', ticket=request.form['ticket']))


# route that gets visited after /enterTicket - it sends the pdf report
@app.route('/getReport/<string:ticket>')
def getReport(ticket):
    tasks = []
    try:
        tasks = db.get_tasks(ticket)
        print(tasks[0], file=sys.stderr)
    except AttributeError:
        return render_template('error.html', typeError=False, unknownTicket=True, noURL=False, noOS=False)
    if not is_done(db.get_ticket(ticket)['id']):
        # find out place in queue
        taskinqueue = tasks[0]
        queue = db.list_tasks(status='pending')
        queue += db.list_tasks(status='running')
        queue = [i for i in queue if i.added_on < taskinqueue.added_on]
        return render_template('notDoneYet.html', queuesize=len(queue))
    tasklist = []
    for i in range(0, len(tasks)):
        reportPath = Path(app.config['CUCKOO_FOLDER'] + str(tasks[i].id) + '/reports/report.pdf')
        tcpPath = Path(app.config['CUCKOO_FOLDER'] + str(tasks[i].id) + '/dump.pcap')
        name = ''
        pdf = False
        tcp = False

        if tasks[i].category == 'url':
            name = tasks[i].target
        elif tasks[i].category == 'file':
            name = os.path.basename(tasks[i].target)
        if reportPath.exists():
            pdf = True
        if tcpPath.exists():
            tcp = True
        tasklist.append((i, name, pdf, tcp))
    return render_template('getReport.html', tasklist=tasklist, ticket=ticket)


# this route answers the pdf report download request
@app.route('/downloadReport/<string:ticket>/<int:index>')
def downloadReport(ticket, index):
    task = db.get_tasks(ticket)[index]
    return send_file(os.path.join(app.config['CUCKOO_FOLDER'] + str(task.id) + '/reports', 'report.pdf'),
                     as_attachment=True)


# this route answers the tcpdump download request
@app.route('/downloadTcp/<string:ticket>/<int:index>')
def downloadTcp(ticket, index):
    task = db.get_tasks(ticket)[index]
    return send_file(os.path.join(app.config['CUCKOO_FOLDER'] + str(task.id), 'dump.pcap'), as_attachment=True)


# route for logins and account registration
@app.route('/loginregister', methods=['GET', 'POST'])
def loginRegister():
    if request.method == 'GET':
        return render_template('LoginRegister.html')
    if request.method == 'POST':
        # check if its a login request
        if 'emailLogin' in request.form:
            email = request.form['emailLogin']
            password = request.form['passwordLogin']
            userId = db.get_user_by_email(email)
            if not userId:
                return render_template('LoginRegister.html', loginError=True)
            if check_password_hash(db.get_model(User, userId).password, password):
                if db.get_model(User, userId).email_authenticated:
                    session['logged_in'] = userId
                else:
                    return redirect(url_for('nowVerify'))
                return redirect(url_for('account'))
            else:
                return render_template('LoginRegister.html', loginError=True)
        # check if its a registration request
        elif 'emailRegister' in request.form:
            email = request.form['emailRegister']
            password = request.form['passwordRegister']
            passwordRep = request.form['passwordRepeatRegister']
            passwordhash = generate_password_hash(password)

            # check if E-Mail matches e-mail-pattern
            if not match(r'[^@]+@[^@]+\.[^@]+', email):
                return render_template('LoginRegister.html', mailFormat=True)

            # check if password fits policies
            if not checkpw(password):
                return render_template('LoginRegister.html', weakPw=True)

            # check if email is already taken
            if db.get_user_by_email(email):
                return render_template('LoginRegister.html', emailTaken=True)
            else:
                # check if password and password repeat match and if yes create account
                if password == passwordRep:
                    newUserId = db.add_user(email, passwordhash, 0)
                    send_verification_mail(newUserId)
                    return render_template('verification.html', send=True)
                else:
                    return render_template('LoginRegister.html', matchError=True)
        else:
            return render_template('LoginRegister.html')


# route for password recovery
@app.route('/forgotPW', methods=['GET', 'POST'])
def forgotPW():
    # TODO send email with reset link

    if 'email' in request.form:
        email = request.form['email']
        userId = db.get_user_by_email(email)
        if userId:
            # generate a new link and add it to database with type password
            link = db.add_verification_link(userId, 'password', str(uuid.uuid4().hex))
            #load email texts
            htmlfile = open('website/templates/passwordReset.html', 'r', encoding="utf8")
            htmltext = htmlfile.read()
            htmlfile.close()
            mailfile = open('website/templates/passwordReset.txt', 'r', encoding="utf8")
            mailtext = mailfile.read()
            mailfile.close()

            # replace placeholders
            placeholders = {
                'LINK': 'http://malwaremuehle.dynip.online/resetpw/' + db.get_model(VerificationLink, link).link}
            htmlmail = replace_placeholder(htmltext, placeholders)
            txtmail = replace_placeholder(mailtext, placeholders)

            # send mail
            send_mail(email, 'Dein Link zur Passwortänderung', txtmail, htmlmail)
            return render_template('forgotpw.html', emailsent=True)
        else:
            return render_template('forgotpw.html', emailsent=True)
    return render_template('forgotpw.html')


# route for email verification
@app.route('/nowVerify', defaults={'link': None}, methods=['GET', 'POST'])
@app.route('/nowVerify/<string:link>', methods=['GET'])
def nowVerify(link):
    # if this route is visited in order to request a verification link
    if link == None:
        if request.method == 'POST':
            email = request.form['email']
            userId = db.get_user_by_email(email)
            # if there is no account with that email pretend there was but dont to anything
            if not userId:
                return render_template('verification.html', send=True)
            send_verification_mail(userId)
            return render_template('verification.html', send=True)
        else:
            return render_template('verification.html')
    # if this route is visited via verification link
    if link:
        try:
            # this function also sets the e-mail-authenticated flag in the database
            db.process_verification_link(link)
        except AttributeError:
            return render_template('verification.html', wrong=True)
        return render_template('verification.html', verified=True)
    return render_template('verification.html')


# route for logged in user
@app.route('/account', methods=['GET', 'POST'])
def account():
    userId = session.get('logged_in')
    if userId:
        tickets = db.get_tickets_by_user(userId)
        ticketval_list = []
        for ticket in tickets:
            ticketval_list.append(ticket['ticket_val'])

        # if user sends form for reset
        if 'passwordreset' in request.form and 'passwordrep' in request.form:
            password = request.form['passwordreset']
            passwordrep = request.form['passwordrep']

            if not checkpw(password):
                return render_template('account.html', tickets=ticketval_list, weakPw=True)

            # change password
            user = db.get_model(User, userId)
            if user:
                if check_password_hash(user.password, password):
                    return render_template('account.html', tickets=ticketval_list, samepass=True)
                elif password == passwordrep:
                    db.update_password(userId, generate_password_hash(password))
                    return render_template('account.html', tickets=ticketval_list, passreset=True)
                else:
                    return render_template('account.html', tickets=ticketval_list, matchError=True)

    return render_template('account.html', notauth=True)


# route for after reset link is clicked
@app.route('/resetpw', defaults={'link': None}, methods=['GET', 'POST'])
@app.route('/resetpw/<string:link>', methods=['GET', 'POST'])
def resetpw(link):
    # if this route is visited without verification link
    if not link:
        return render_template('resetpw.html')
    else:
        # if the html form was filled (so method is post)
        if 'passwordreset' in request.form:
            password = request.form['passwordreset']
            passwordrep = request.form['passwordrep']
            passwordhash = generate_password_hash(password)

            # if the password fits the policies
            if not checkpw(password):
                return render_template('resetpw.html', auth=True, weakPw=True)

            # change password
            if password == passwordrep:
                try:
                    # this checks if the link is valid and if yes changes the password
                    db.process_verification_link(link, password=passwordhash)
                except AttributeError:
                    return render_template('resetpw.html', badlink=True)
                return render_template('resetpw.html', passreset=True)
            else:
                return render_template('resetpw.html', auth=True, matchError=True)
        return render_template('resetpw.html', auth=True)


# route function for logout
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))


# routes for library
@app.route('/library/', defaults={'page': 1}, methods=['GET', 'POST'])
@app.route('/library/<int:page>', methods=['GET', 'POST'])
def library(page):
    # set max number of result per page
    per_page = 15

    # filter function
    def is_anon_task(sample):
        try:
            if sample["task_id"]:
                task = db.get_model(Task, sample["task_id"])
                if task and task.ticket_id:
                    uid = db.get_model(Ticket, task.ticket_id).user_id
                    return uid is None or uid is session.get('logged_in')
                else:
                    return True
        except AttributeError:
            return True

    if request.method == 'GET':
        # first load of page
        # call db function
        results = db.find_by_filter()

        # filter result only for anonymous user
        results = list(filter(is_anon_task, results if results else []))

        # set max number of pages to load
        max_pages = int(math.ceil(len(results) / per_page))

        # divide the result into parts
        paged_result = results[((page - 1) * per_page):(page * per_page)]
        return render_template('library.html', results=paged_result, max_pages=max_pages, page=page)
    elif request.method == 'POST':
        # when user inputs something
        # text input
        filtertext = request.form.get('textinput')
        filterhash = request.form.get('hashinput')
        # select option
        filterdate = request.form.get('date')
        filterscore = request.form.get('score')

        # check user input, date needs to be converted to datetime
        if filterdate == '0d':
            filterdate = datetime.today()
        elif filterdate == '1d':
            filterdate = datetime.today() - timedelta(days=1)
        elif filterdate == '10d':
            filterdate = datetime.today() - timedelta(days=10)

        # set score to integer. Filter could be empty, and int() cannot take nonetype
        if filterscore:
            filterscore = int(filterscore)

        # call db function
        results = db.find_by_filter(filename=filtertext if filtertext else "%",
                                    score=filterscore,
                                    md5=filterhash if filterhash else "%",
                                    sha256=filterhash if filterhash else "%",
                                    date=filterdate)

        # filter result only for anonymous user
        results = list(filter(is_anon_task, results if results else []))

        # set default for text filter, otherwise it only returns empty string
        if not filtertext:
            filtertext = "kein Text"

        # set default for hash filter, otherwise it only returns empty string
        if not filterhash:
            filterhash = "kein Hash"

        # set max number of pages to load
        max_pages = int(math.ceil(len(results) / per_page))

        # divide the result into parts
        paged_result = results[((page - 1) * per_page):(page * per_page)]
        return render_template('library.html', filter=filtertext, date=filterdate,
                               score=filterscore, page=page, max_pages=max_pages,
                               hash=filterhash, results=paged_result)
    return render_template('library.html')


# routes for library download
@app.route('/libdown', methods=['GET'])
@app.route('/libdown/<int:tid>', methods=['GET'])
def libdown(tid):
    # check if tid is anonym function
    def is_anon_tid(tid):
        try:
            if tid:
                task = db.get_model(Task,tid)
                if task and task.ticket_id:
                    uid = db.get_model(Ticket, task.ticket_id).user_id
                    return uid is None or uid is session.get('logged_in')
                else:
                    return True
        except AttributeError:
            return True

    # check if tid is anon
    if is_anon_tid(tid):
        # download reports belonging to result shown in library
        return send_file(os.path.join(app.config['CUCKOO_FOLDER'] + str(tid) + '/reports', 'report.pdf'),
                         as_attachment=True)
    else:
        return render_template('library.html')

# routes for statistic site
@app.route('/statistics_general')
def statistik():
    # Getting Data for Statistics
    # most scanned samples

    top_samples = {'sampleMd5': [],
                   'filenames': [],
                   'count': [],
                   'rgb': []}
    # counter for fixed rgb values
    counter = 0


    list_top_samples = db.get_top_samples()
    # Initialize List with matching length


    for sample in list_top_samples:

        filenames = list()
        compromised_filenames = list()
        counter = counter % 10
        view_sample = db.view_sample(sample_id=sample[0])
        tasks = db.list_tasks(sample_id=sample[0])

        # Getting Filenames per tasks
        for task in tasks:
            filenames.append(" " + db.get_target(task.id))

        compromised_filenames = list(set(filenames))
        top_samples['sampleMd5'].append(view_sample.md5)
        top_samples['filenames'].append(compromised_filenames)
        top_samples['count'].append(sample[1])
        top_samples['rgb'].append(Statistics.random_rgb[counter])
        counter += 1

    # timeline of number of scans from last 12 months
    result_general_scans = db.get_monthly_scans()
    list_month_names = []

    general_scans = {'month': list(result_general_scans.keys())[::-1],
                     'count': list(result_general_scans.values())[::-1]}

    # mapping int month values to actual month names
    for month in general_scans['month']:
        list_month_names.append(Statistics.month_names[month])
    general_scans['month'] = list_month_names

    # number of evil IP addresses per country
    top_countries = db.get_country_distribution()

    # general distribution of OS
    dist_os = {'platform': [],
               'count': []}

    for obj in db.get_scans_per_os():
        dist_os['platform'].append(obj[0])
        dist_os['count'].append(obj[1])

    return render_template('statistics_general.html', top_samples=top_samples,
                           general_scans=general_scans,
                           top_countries=top_countries, dist_os=dist_os)


# routes for statistic site
@app.route('/statistics_score', methods=['GET', 'POST'])
def statistics_score():
    # default score=10 when website is newly loaded
    score = Statistics.default_score

    # general distribution of scores
    str_list = []
    result_dist_scores = db.count_samples_per_score()
    dist_scores = {'score': list(result_dist_scores.keys()),
                   'count': list(result_dist_scores.values()),
                   'rgb': []}

    # converting int score values to str and add matching rgb values
    for obj in dist_scores['score']:
        str_list.append(str(obj))
        dist_scores['rgb'].append(Statistics.rgb_values[obj])
    dist_scores['score'] = str_list
    app.logger.info(dist_scores)

    # if user whishes to filter using score
    if 'score' in request.form:
        score = int(request.form.get('score'))

    # timeline per score
    result_timeline_of_score = db.get_scans_per_month(score=score)
    list_month_names = []

    timeline_of_score = {'month': list(result_timeline_of_score.keys())[::-1],
                         'count': list(result_timeline_of_score.values())[::-1],
                         'rgb': Statistics.rgb_values[score]}

    # mapping int month values to actual month names
    for month in timeline_of_score['month']:
        list_month_names.append(Statistics.month_names[month])
    timeline_of_score['month'] = list_month_names

    # top scanned malware per score default = 10

    top_of_score = {'sampleMd5': [],
                    'count': [],
                    'filenames':[],
                    'rgb': Statistics.rgb_values[score]}
    list_top_score = db.get_samples_per_score(score)

    for sample in list_top_score:
        filenames = list()
        compromised_filenames = list()
        view_sample = db.view_sample(sample_id=sample[0])
        tasks = db.list_tasks(sample_id=sample[0])

        # Getting Filenames per tasks
        for task in tasks:
            filenames.append(" " + db.get_target(task.id))
        compromised_filenames = list(set(filenames))
        top_of_score['sampleMd5'].append(view_sample.md5)
        top_of_score['filenames'].append(compromised_filenames)
        top_of_score['count'].append(sample[1])

    return render_template('statistics_score.html', timeline_of_score=timeline_of_score, dist_scores=dist_scores,
                           top_of_score=top_of_score, score=score)


# routes for statistic site
@app.route('/statistics_transmissions')
def statistics_transmissions():
    # most used file types for transmitting malware
    top_files = {'file_type': [],
                 'count': [],
                 'rgb': []}

    # counter for fixed rgb values
    counter = 0

    # adding rgb values dynamically to number of top_files entries
    for filetype in db.get_filetype_distribution():
        counter = counter % 10
        top_files['file_type'].append(filetype[0])
        top_files['count'].append(filetype[1])
        top_files['rgb'].append(Statistics.random_rgb[counter])
        counter += 1

    # most used way of transmitting data
    transmission_counts = db.get_category_distribution()
    top_transmissions = {'category': list(transmission_counts.keys()),
                         'count': list(transmission_counts.values()),
                         'rgb': []}

    # counter for fixed rgb values
    counter = 0

    # adding rgb values dynamically to number of top_transmissions entries
    for category in top_transmissions['category']:
        counter = counter % 10
        top_transmissions['rgb'].append(Statistics.random_rgb[counter])
        counter += 1

    return render_template('statistics_transmissions.html', top_files=top_files, top_transmissions=top_transmissions)


# routes for statistic site
@app.route('/statistics_malware', methods=['GET'])
def statistics_malware():
    filenames= list()
    compromised_filenames=""
    # md5 hash of sample recieved from library.html
    md5_hash = request.args.get('md5')
    #tasks to get filenames
    sample = db.find_sample(md5=md5_hash)
    tasks = db.list_tasks(sample_id=sample.id)
    for task in tasks:
        filenames.append(db.get_target(task.id))

    filenames=list(set(filenames))
    for filename in filenames: compromised_filenames += filename
    #time line for sample
    result_timeline_of_sample = db.get_scans_per_month(md5=md5_hash)
    list_month_names = []

    timeline_of_sample = {'month': list(result_timeline_of_sample.keys())[::-1],
                          'count': list(result_timeline_of_sample.values())[::-1],
                          'rgb': ''}

    # mapping int month values to actual month names and adding random rgb value
    for month in timeline_of_sample['month']:
        list_month_names.append(Statistics.month_names[month])

    timeline_of_sample['rgb'] = Statistics.random_rgb[randint(0, 9)]
    timeline_of_sample['month'] = list_month_names
    # number of scans of the sample
    sample_count = db.count_scans_per_sample(md5=md5_hash)

    return render_template('statistics_malware.html', timeline_of_sample=timeline_of_sample, sample_count=sample_count,
                           md5_hash=md5_hash, compromised_filenames=compromised_filenames)


# route for adminpage only accessable with logged in user user.privilege_level = 3
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    user = session.get('logged_in')
    if not user:
        abort(404)
    # check if a admin is logged in, if not pretend there is no page /admin
    if db.get_model(User,user).privilege_level != 99:
        abort(404)
    if request.method == 'GET':
        dbconnection = True
        # make a list of lists with size 4 of all running tasks to display at the admin page
        try:
            runningTasks = db.list_tasks(status='running')
        except:
            dbconnection = False

        runningTasks = [task.to_dict() for task in runningTasks]
        # shorten tagret path so its only the filename
        for task in runningTasks:
            task['target'] = os.path.basename(task['target'])
        runningTasks4Packs = [runningTasks[x:x + 4] for x in range(0, len(runningTasks), 4)]

        status = get_cuckoo_status()

        totalram = to_gb(status['memtotal'])
        freeram = to_gb(status['memavail'])

        # get free disk space and turn bytes into gigabytes
        totalspace = str(round(status['diskspace']['analyses']['total'] / 1024 / 1024 / 1024, 2))
        freespace = str(round(status['diskspace']['analyses']['free'] / 1024 / 1024 / 1024, 2))
        usedspace = str(round(status['diskspace']['analyses']['used'] / 1024 / 1024 / 1024, 2))

        #get the cpuusage and the nr. of machines connected to cuckoo and analyzing right now
        cpuload = status['cpuload']
        machinesavailable = status['machines']['available']
        machinestotal = status['machines']['total']

        adminlist = db.get_users_by_privilege(99)
        adminlist = [adminuser['email'] for adminuser in adminlist]

        return render_template('admin.html', tasklist=runningTasks4Packs, db=dbconnection, totalram=totalram,
                               freeram=freeram, cpuload=cpuload, machinesavailable=machinesavailable,
                               machinestotal=machinestotal, totalspace=totalspace, freespace=freespace, usedspace=usedspace, adminlist=adminlist)
    elif request.method == 'POST':
        userId = db.get_user_by_email(request.form['email'])
        privilege_level = request.form['priv']
        if userId:
            db.set_user_privilege(privilege_level, userId)
        return redirect(url_for('admin'))
