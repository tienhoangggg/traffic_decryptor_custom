"""
tab._extender
tab._controller
tab._editable
tab._helpers
tab._stdout
tab._txtInput
tab._originalMessage
tab._isRequest
"""

DEBUG = True


import json
import copy
import base64
import traceback
import pyaes

def is_debug(tab):
    # tab._stdout.println("Is Debug?: {}".format(DEBUG))
    return DEBUG


# contain detection logic, return True if this request/response contains ecrypted data
def is_encrypted(tab, content, isRequest):
    #if it is response from /api endpoint (and sub-endpoints) so all body is encrypted
    if isRequest:
        return False
    else:
        return True


# contain logic for decrypt request traffic, call setText with decrypted data
def set_request_text(tab, content, isRequest):
    set_not_encrypted_text(tab, content, isRequest)


# contain logic for decrypt response traffic, call setText with decrypted data
def set_response_text(tab, content, isRequest):
    if is_encrypted(tab, content, isRequest):
        info, body = extract_info(tab, content, isRequest)
        decrypted_data = decrypt_data(body)
        if decrypted_data != "ERROR_VCS_DECRYPT_123456789":
            try:
                decrypted_data = json.dumps(json.loads(decrypted_data), indent=4)
            except:
                pass
            tab._txtInput.setText(content[0:info.getBodyOffset()].tostring() + decrypted_data)
        else:
            tab._txtInput.setText(content[0:info.getBodyOffset()].tostring() + body)
    else:
        set_not_encrypted_text(tab, content, isRequest)


def set_error_text(tab, e):
    # tab._txtInput.setText("Error processing content: {}".format(e).encode("utf-8"))
    tab._txtInput.setText(traceback.format_exc())


def set_not_encrypted_text(tab, content, isRequest):
    return tab._txtInput.setText("No encrypted data found!")


def is_text_modified(tab):
    if is_debug(tab):
        tab._stdout.println("Edited?: {}".format(tab._txtInput.isTextModified()))

    return tab._txtInput.isTextModified()


def build_request(tab):
    #raw data, no json
    data = tab._txtInput.getText()
    return data


def build_response(tab):
    #raw data, no json
    data = tab._txtInput.getText()
    return data

# ENCRYPT / DECRYPT

def decrypt_data(encrypted_data):
    try:
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationECB(b"e5ch*sfsAl8rX@H#"))
        decrypted_data = decrypter.feed(encrypted_data_bytes) + decrypter.feed()
        return decrypted_data.decode('utf-8')
    except Exception as e:
        return "ERROR_VCS_DECRYPT_123456789"

def encrypt_data(plaintext):
    encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationECB(b"e5ch*sfsAl8rX@H#"))
    ciphertext = encrypter.feed(plaintext.encode('utf-8')) + encrypter.feed()
    encrypted_data = base64.b64encode(ciphertext).decode('utf-8')

    return encrypted_data

# HELPERS


def extract_info(tab, content, isRequest):
    if isRequest:
        info = tab._helpers.analyzeRequest(content)
    else:
        info = tab._helpers.analyzeResponse(content)

    body = content[info.getBodyOffset() :].tostring()

    return info, body
