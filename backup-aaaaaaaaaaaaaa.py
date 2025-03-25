import re
from flask import Flask, jsonify, request, send_file
from main import app, con
from flask_bcrypt import generate_password_hash, check_password_hash
from fpdf import FPDF
from flask import request
import os
import jwt
from flask_cors import CORS

CORS(app, resources={r"/": {"origins": "*"}},  # Permite todas as origens
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# CADASTRO
app.config.from_pyfile('config.py')

senha_secreta = app.config['SECRET_KEY']

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


def generate_token(user_id):
    # Esse payload armazena os dados que vão incorporar no token (aqui é o ID)
    payload = {'id_usuario': user_id}
    # Geração do token com o algoritmo de hash HS256 usando uma senha secreta
    token = jwt.encode(payload, senha_secreta, algorithm='HS256')
    # Retorna o token
    return token


def remover_bearer(token):
    # Verifica se o token começa com a string 'Bearer '
    if token.startswith('Bearer '):
        # retorna sem a parte 'Bearer '
        return token[len('Bearer '):]
    else:
        return token


@app.route('/cadastro', methods=['GET'])
def cadastro():
    tipo_usuario = request.args.get('tipo',
                                    type=int)  # Essa linha utiliza 'request.args.get' para adquirir o valor do tipo armazenado no banco de dados, vimos sobre esse código no site: https://stackoverflow.com/questions/34671217/in-flask-what-is-request-args-and-how-is-it-used

    cur = con.cursor()

    if tipo_usuario == 2:
        cur.execute("SELECT id_usuario, nome, e_mail, senha, tipo FROM usuario WHERE tipo = 2")
    elif tipo_usuario == 3:
        cur.execute("SELECT id_usuario, nome, e_mail, senha, tipo FROM usuario WHERE tipo = 3")
    else:
        cur.execute("SELECT id_usuario, nome, e_mail, senha, tipo FROM usuario")

    usuarios = cur.fetchall()

    doador_dic = []
    ong_dic = []

    for usuario in usuarios:
        id_usuario = usuario[0]
        nome = usuario[1]
        e_mail = usuario[2]
        senha = usuario[3]
        tipo = usuario[4]

        if tipo == 3:
            cur.execute(
                "SELECT nome, e_mail, senha FROM usuario WHERE id_usuario = ?",
                (id_usuario,))

            doador_dic.append({
                'id_usuario': id_usuario,
                'nome': nome,
                'e_mail': e_mail,
                'senha': senha
            })
        elif tipo == 2:
            cur.execute(
                "SELECT cnpj, categoria, descricao_da_causa, cep, chave_pix, num_agencia, num_conta, nome_banco FROM usuario WHERE id_usuario = ?",
                (id_usuario,))
            ong_info = cur.fetchone()

            ong_dic.append({
                'id_usuario': id_usuario,
                'nome': nome,
                'e_mail': e_mail,
                'senha': senha,
                'cnpj': ong_info[0],
                'categoria': ong_info[1],
                'descricao_da_causa': ong_info[2],
                'cep': ong_info[3],
                'chave_pix': ong_info[4],
                'num_agencia': ong_info[5],
                'num_conta': ong_info[6],
                'nome_banco': ong_info[7]
            })

    if doador_dic:
        return jsonify(mensagem='Registro de Cadastro de Doadores', doadores=doador_dic)
    elif ong_dic:
        return jsonify(mensagem='Registro de Cadastro de ONGs', ongs=ong_dic)
    else:
        return jsonify(mensagem='Nenhum dado encontrado')


def validar_senha(senha):
    padrao = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%¨&*])(?=.*\d).{8,}$'

    if re.fullmatch(padrao, senha):
        return True
    else:
        return False


@app.route('/cadastro', methods=['POST'])
def cadastro_post():
    data = request.get_json()
    nome = data.get('nome')
    e_mail = data.get('e_mail')
    senha = data.get('senha')
    cnpj = data.get('cnpj')
    categoria = data.get('categoria')
    descricao_da_causa = data.get('descricao_da_causa')
    cep = data.get('cep')
    chave_pix = data.get('chave_pix')
    num_agencia = data.get('num_agencia')
    num_conta = data.get('num_conta')
    nome_banco = data.get('nome_banco')

    tipo_usuario = int(data.get('tipo'))

    if not validar_senha(senha):
        return jsonify({
                           "error": 'A sua senha precisa ter pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula, um número e um caractere especial.'}), 401

    cursor = con.cursor()

    cursor.execute("SELECT 1 FROM usuario WHERE E_MAIL = ?", (e_mail,))

    if cursor.fetchone():
        return jsonify({"error": "E-mail já cadastrado!"}), 400

    senha = generate_password_hash(senha).decode('utf-8')

    if tipo_usuario == 3:
        cursor.execute("INSERT INTO USUARIO(NOME, E_MAIL, SENHA, tipo, ativo) VALUES (?, ?, ?, ?, ?)",
                       (nome, e_mail, senha, 3, 1))
        con.commit()
        cursor.close()

        return jsonify({
            'message': "Registro realizado com sucesso!",
            'usuario': {
                'nome': nome,
                'e_mail': e_mail,
                'senha': senha
            }
        })

    elif tipo_usuario == 2:
        cursor.execute(
            "INSERT INTO USUARIO(NOME, E_MAIL, SENHA, CNPJ, CATEGORIA, DESCRICAO_DA_CAUSA, CEP, CHAVE_PIX, NUM_AGENCIA, NUM_CONTA, NOME_BANCO, ATIVO, tipo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (nome, e_mail, senha, cnpj, categoria, descricao_da_causa, cep, chave_pix, num_agencia, num_conta,
             nome_banco, 1, 2))
        con.commit()
        cursor.close()
        return jsonify({
            'message': "Registro realizado com sucesso!",
            'usuario': {
                'nome': nome,
                'e_mail': e_mail,
                'senha': senha,
                'cnpj': cnpj,
                'categoria': categoria,
                'descricao_da_causa': descricao_da_causa,
                'cep': cep,
                'chave_pix': chave_pix,
                'num_agencia': num_agencia,
                'num_conta': num_conta,
                'nome_banco': nome_banco
            }
        })
    else:
        return jsonify({
            'error': "Tipo Selecionado Inválido!"
        })


@app.route('/cadastro/<int:id>', methods=['PUT'])
def cadastro_put(id):
    tipo_usuario = request.args.get('tipo',
                                    type=int)  # Essa linha utiliza 'request.args.get' para adquirir o valor do tipo armazenado no banco de dados, vimos sobre esse código no site: https://stackoverflow.com/questions/34671217/in-flask-what-is-request-args-and-how-is-it-used
    cursor = con.cursor()
    cursor.execute(
        "select id_usuario, nome, e_mail, senha, cnpj, categoria, descricao_da_causa, cep, chave_pix, num_agencia, num_conta, nome_banco, tipo, endereco, complemento, nome_resp, telefone, site_url, facebook, instagram from usuario WHERE id_usuario = ?",
        (id,))
    usuario = cursor.fetchone()

    tipo_usuario = usuario[12]
    senha_armazenada = usuario[3]
    e_mail_armazenado = usuario[2]

    if not usuario:
        cursor.close()
        return jsonify({"error": 'Registro não encontrado.'}), 401

    if tipo_usuario == 3:
        data = request.get_json()
        nome = data.get('nome')
        e_mail = data.get('e_mail')
        senha = data.get('senha')

        cursor = con.cursor()

        if e_mail_armazenado != e_mail:
            cursor.execute("SELECT 1 FROM usuario WHERE E_MAIL = ?", (e_mail,))
            if cursor.fetchone():
                return jsonify({"error": "E-mail já cadastrado!"}), 400

        if senha_armazenada != senha:
            if not validar_senha(senha):
                return jsonify({
                                   "error": 'A sua senha precisa ter pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula, um número e um caractere especial.'}), 401

            senha = generate_password_hash(senha).decode('utf-8')

        cursor.execute("UPDATE usuario SET NOME = ?, E_MAIL = ?, SENHA = ? WHERE ID_USUARIO = ?",
                       (nome, e_mail, senha, id))
        con.commit()
        cursor.close()

        return jsonify({
            'message': "Cadastro atualizado com sucesso!",
            'usuario': {
                'id_usuario': id,
                'nome': nome,
                'e_mail': e_mail,
                'senha': senha
            }
        }), 200

    elif tipo_usuario == 2:
        data = request.get_json()
        nome = data.get('nome')
        e_mail = data.get('e_mail')
        senha = data.get('senha')
        cnpj = data.get('cnpj')
        categoria = data.get('categoria')
        descricao_da_causa = data.get('descricao_da_causa')
        cep = data.get('cep')
        chave_pix = data.get('chave_pix')
        num_agencia = data.get('num_agencia')
        num_conta = data.get('num_conta')
        nome_banco = data.get('nome_banco')
        endereco = data.get('endereco')
        complemento = data.get('complemento')
        nome_resp = data.get('nome_resp')
        telefone = data.get('telefone')
        site_url = data.get('site_url')
        facebook = data.get('facebook')
        instagram = data.get('instagram')

        print(senha)

        cursor = con.cursor()

        cursor.execute("SELECT 1 FROM usuario WHERE E_MAIL = ?", (e_mail,))

        if e_mail_armazenado != e_mail:
            cursor.execute("SELECT 1 FROM usuario WHERE E_MAIL = ?", (e_mail,))
            if cursor.fetchone():
                return jsonify({"error": "E-mail já cadastrado!"}), 400

        if senha_armazenada != senha:
            if not validar_senha(senha):
                return jsonify({
                                   "error": 'A sua senha precisa ter pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula, um número e um caractere especial.'}), 401

            senha = generate_password_hash(senha).decode('utf-8')

        cursor.execute(
            "UPDATE usuario SET NOME = ?, E_MAIL = ?, SENHA = ?, CNPJ = ?, CATEGORIA = ?, DESCRICAO_DA_CAUSA = ?, CEP = ?, CHAVE_PIX = ?, NUM_AGENCIA = ?, NUM_CONTA = ?, NOME_BANCO = ?, ENDERECO = ?, COMPLEMENTO = ?, NOME_RESP = ?, TELEFONE = ?, SITE_URL = ?, FACEBOOK = ?, INSTAGRAM = ? WHERE ID_USUARIO = ?",
            (nome, e_mail, senha, cnpj, categoria, descricao_da_causa, cep, chave_pix, num_agencia, num_conta,
             nome_banco, endereco, complemento, nome_resp, telefone, site_url, facebook, instagram, id))
        con.commit()
        cursor.close()

        return jsonify({
            'message': "Cadastro atualizado com sucesso!",
            'usuario': {
                'id_usuario': id,
                'nome': nome,
                'e_mail': e_mail,
                'senha': senha,
                'cnpj': cnpj,
                'categoria': categoria,
                'descricao_da_causa': descricao_da_causa,
                'cep': cep,
                'chave_pix': chave_pix,
                'num_agencia': num_agencia,
                'num_conta': num_conta,
                'endereco': endereco,
                'complemento': complemento,
                'nome_resp': nome_resp,
                'telefone': telefone,
                'site_url': site_url,
                'facebook': facebook,
                'instagram': instagram
            }
        })
    return jsonify({
        'message': "Cadastro atualizado com sucesso!"})


@app.route('/cadastro/<int:id>', methods=['DELETE'])
def deletar_cadastro(id):
    cursor = con.cursor()

    cursor.execute("SELECT 1 FROM usuario WHERE ID_USUARIO = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Registro não encontrado."}), 404

    cursor.execute("DELETE FROM usuario WHERE ID_USUARIO = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Cadastro excluído com sucesso!",
        'id_usuario': id
    })


tentativas = 0


# LOGIN
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    e_mail = data.get('e_mail')
    senha = data.get('senha')

    global tentativas

    cursor = con.cursor()
    cursor.execute("SELECT nome, e_mail, senha, tipo, id_usuario, ativo FROM usuario WHERE e_mail = ?", (e_mail,))
    login_data = cursor.fetchone()

    # Verifique se login_data é None antes de acessar os dados
    if login_data is None:
        cursor.close()
        return jsonify({'error': "Credenciais não encontradas"}), 400

    # Se o usuário não estiver ativo
    if login_data[5] != 1:
        return jsonify({'message': "Usuário Inativo!"}), 400

    senha_hash = login_data[2]

    # Verifica se a senha está correta
    if check_password_hash(senha_hash, senha):
        token = generate_token(login_data[4])

        # Retorna a resposta com o tipo de usuário
        return jsonify({
            'message': "Login feito com sucesso!",
            'tipo': login_data[3],
            'nome': login_data[0],
            'e_mail': login_data[1],
            'id_usuario': login_data[4],
            'token': token
        }), 200

    if login_data[3] != 1:
        tentativas += 1
        print(tentativas)

        if tentativas == 3:
            cursor.execute("UPDATE usuario SET ativo = 0 WHERE id_usuario = ?", (login_data[4],))
            tentativas = 0
            con.commit()

            cursor.close()

            return jsonify({'error': "Usuário Inativo!"}), 400

    return jsonify({'message': "Erro no login!"}), 400


@app.route('/usuario/relatorio', methods=['GET'])
def usuario_relatorio():
    # CONSULTA COM BANCO
    cursor = None
    try:
        cursor = con.cursor()
        cursor.execute("SELECT id_usuario, nome, e_mail FROM usuario")
        usuarios = cursor.fetchall()
    finally:
        if cursor:
            cursor.close()

    # CRIAÇÃO DE PDF
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", style='B', size=16)
    pdf.cell(200, 10, "Relatório de Usuários", ln=True, align='C')

    # ADICIONANDO UMA LINHA SEPARADORA PARA MELHOR ORGANIZAÇÃO
    pdf.ln(5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    # INSERINDO OS DADOS
    pdf.set_font("Arial", size=12)
    for usuario in usuarios:
        pdf.cell(200, 10, f"ID: {usuario[0]} - Nome: {usuario[1]} - E-mail: {usuario[2]}", ln=True)

    # ADICIONANDO O TOTAL DE CADASTRADOS
    contador_usuarios = len(usuarios)
    pdf.ln(10)
    pdf.set_font("Arial", style='B', size=12)
    pdf.cell(200, 10, f"Total de usuários cadastrados: {contador_usuarios}", ln=True, align='C')

    # SALVANDO E ENVIANDO O PDF
    pdf_path = "relatorio_usuarios.pdf"
    pdf.output(pdf_path)
    return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')


@app.route('/imagem/<int:id>', methods=['PUT', 'OPTIONS'])
def imagem(id):
    # # ADICIONA O CAMINHO DA RAIZ DO PROJETO
    # token = request.headers.get('Authorization')
    # print(token)
    #
    # if not token:
    #     return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    #
    # token = remover_bearer(token)
    # try:
    #     payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
    #     id_usuario = payload['id_usuario']
    # except jwt.ExpiredSignatureError:
    #     return jsonify({'mensagem': 'Token expirado'}), 401
    # except jwt.InvalidTokenError:
    #     return jsonify({'mensagem': 'Token inválido'}), 401

    # Recebendo os dados do formulário (não JSON)/ CAPTURA IMAGEM ENVIADA NA ROTA
    endereco = request.form.get('endereco')
    complemento = request.form.get('complemento')
    nome_resp = request.form.get('nome_resp')
    telefone = request.form.get('telefone')
    site_url = request.form.get('site_url')
    facebook = request.form.get('facebook')
    instagram = request.form.get('instagram')

    imagem = request.files.get('imagem')  # Arquivo enviado

    cursor = con.cursor()

    # Verifica se já existe
    cursor.execute("SELECT 1 FROM usuario WHERE id_usuario = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Usuário não encontrado"}), 400

    cursor.execute(
        "UPDATE usuario set endereco = ?, complemento = ?, nome_resp = ?, telefone = ?, site_url = ?, facebook = ?, instagram = ? WHERE ID_USUARIO = ?",
        (endereco, complemento, nome_resp, telefone, site_url, facebook, instagram, id))
    con.commit()
    cursor.close()

    # Salvar a imagem se for enviada
    imagem_path = None
    if imagem:
        nome_imagem = f"{id}.jpeg"  # Define o nome fixo com .jpeg
        pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "Livros")
        os.makedirs(pasta_destino, exist_ok=True)
        imagem_path = os.path.join(pasta_destino, nome_imagem)
        imagem.save(imagem_path)

    cursor.close()

    # VERIFICA SE A IMAGEM FOI SALVA
    return jsonify({
        'message': "Usuário cadastrado com sucesso!",
        'usuario': {
            'id': id,
            'imagem_path': imagem_path,
            'endereco': endereco,
            'complemento': complemento,
            'nome_resp': nome_resp,
            'telefone': telefone,
            'site_url': site_url,
            'facebook': facebook,
            'instagram': instagram
        }
    }), 201
