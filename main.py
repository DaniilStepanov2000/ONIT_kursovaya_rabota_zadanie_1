from flask import Flask, render_template, redirect, request
from Crypto.Cipher import DES
from Cryptodome.Cipher import AES

app = Flask(__name__)

data = {'password_phrase': ''}
use_algorithm = {'DES': True}
some_stuff = {'nonce': b''}


def pad(text):
    if len(text) % 8 == 0:
        return text
    while len(text) % 8 != 0:
        text = text + b' '
    return text


def aes_encrypt_file(password_phrase, path):
    file_data = read_file(path)

    password_phrase_correct = str(abs(hash(password_phrase)) % (10 ** 16))
    if len(password_phrase_correct) == 15:
        password_phrase_correct = password_phrase_correct + password_phrase_correct[-1]

    print('correct psw 1: {}'.format(password_phrase_correct))

    aes = AES.new(password_phrase_correct.encode(), AES.MODE_EAX)
    nonce = aes.nonce
    some_stuff['nonce'] = nonce
    ciphertext, _ = aes.encrypt_and_digest(file_data)
    print('ciphertext: {}'.format(ciphertext))

    write_file(path, ciphertext)


def aes_decrypt_file(password_phrase, path):
    file_data = read_file(path)
    print('file data: {}'.format(file_data))
    password_phrase_correct = str(abs(hash(password_phrase)) % (10 ** 16))
    if len(password_phrase_correct) == 15:
        password_phrase_correct = password_phrase_correct + password_phrase_correct[-1]
    print('correct psw 2: {}'.format(password_phrase_correct))
    aes = AES.new(password_phrase_correct.encode(), AES.MODE_EAX, nonce=some_stuff['nonce'])
    plaintext = aes.decrypt(file_data)
    print('plain text: {}'.format(plaintext.decode('ascii')))

    write_file(path, plaintext)


def des_encrypt_file(password_phrase, path):
    file_data = read_file(path)
    pad_file_data = pad(file_data)

    print('paf file data: {}'.format(pad_file_data))

    # check len of password_phrase_correct (because it can be less than 8)
    password_phrase_correct = str(abs(hash(password_phrase)) % (10 ** 8))
    if len(password_phrase_correct) == 7:
        password_phrase_correct = password_phrase_correct + password_phrase_correct[-1]
    des = DES.new(password_phrase_correct, DES.MODE_ECB)
    encrypt_result = des.encrypt(pad_file_data)
    print('encrypt result: {}'.format(encrypt_result))
    print('len encrypt file: {}'.format(len(encrypt_result)))

    write_file(path, encrypt_result)


def des_decrypt_file(password_phrase, path):
    file_data = read_file(path)
    print('file data: {}'.format(file_data))
    print('len file data: {}'.format(len(file_data)))

    password_phrase_correct = str(abs(hash(password_phrase)) % (10 ** 8))
    if len(password_phrase_correct) == 7:
        password_phrase_correct = password_phrase_correct + password_phrase_correct[-1]

    des = DES.new(password_phrase_correct, DES.MODE_ECB)
    decrypt_result = des.decrypt(file_data)

    print('decrypt result: {}'.format(decrypt_result))
    write_file(path, decrypt_result)


def encrypt_manager(password_phrase, path, algorithm):
    if algorithm == 'DES':
        des_encrypt_file(password_phrase, path)
    else:
        aes_encrypt_file(password_phrase, path)


def decrypt_manager(password_phrase, path, algorithm):
    if algorithm == 'DES':
        des_decrypt_file(password_phrase, path)
    else:
        aes_decrypt_file(password_phrase, path)


def read_file(path):
    file = open(path, 'rb')
    data = file.read()
    file.close()

    return data


def write_file(path, data):
    file = open(path, 'wb')
    file.write(data)
    file.close()


@app.route('/', methods=['GET'])
@app.route('/decrypt_encrypt_file', methods=['GET'])
def decrypt_encrypt_file():
    return render_template('decrypt_encrypt_file.html')


@app.route('/do_encrypt', methods=['GET'])
def do_encrypt():
    return render_template('do_encrypt.html')


@app.route('/do_decrypt', methods=['GET'])
def do_decrypt():
    msg = 'DES' if use_algorithm['DES'] else 'AES'
    return render_template('do_decrypt.html', message=msg)


@app.route('/encrypt', methods=['POST'])
def encrypt():
    result = request.form.to_dict()
    print('psw encr: {}'.format(data['password_phrase']))
    data['password_phrase'] = result['password_phrase']
    if result['algorithm'] == 'DES':
        use_algorithm['DES'] = True
    else:
        use_algorithm['DES'] = False
    encrypt_manager(result['password_phrase'], result['path'], result['algorithm'])
    return redirect('/decrypt_encrypt_file')


@app.route('/decrypt', methods=['POST'])
def decrypt():
    print('psw phrase decr: {}'.format(data['password_phrase']))
    msg = 'DES' if use_algorithm['DES'] else 'AES'
    result = request.form.to_dict()
    if data['password_phrase'] != result['password_phrase']:
        return render_template('do_decrypt.html', msg='The password phrase is incorrect!', message=msg)
    if use_algorithm['DES']:
        algorithm = 'DES'
    else:
        algorithm = 'AES'
    decrypt_manager(result['password_phrase'], result['path'], algorithm)
    return redirect('/decrypt_encrypt_file')


if __name__ == '__main__':
    app.run(debug=True)
