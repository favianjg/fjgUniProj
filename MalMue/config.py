import os
import datetime

class Config(object):
    SECRET_KEY = os.urandom(32)
    # TODO: Change favians path to server when running on server
    CUCKOO_FOLDER = '/home/cuckoo/.cuckoo/storage/analyses/'
    UPLOAD_FOLDER = '/home/mmusr1/venv/uploads' #muss noch mkdir machen bevor server test - Pascal
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024 #100MB Upload limit