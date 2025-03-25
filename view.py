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
    cur = con.cursor()

    cur.execute("SELECT id_usuario, nome, e_mail, senha, tipo, ativo, cnpj, categoria, descricao_da_causa, cep, chave_pix, num_agencia, num_conta, nome_banco, endereco, complemento, nome_resp, telefone, site_url, facebook, instagram FROM usuario")
    usuarios = cur.fetchall()

    usuarios_dic = []

    for usuario in usuarios:
        id_usuario = usuario[0]
        nome = usuario[1]
        e_mail = usuario[2]
        senha = usuario[3]
        tipo = usuario[4]
        ativo = usuario[5]
        cnpj = usuario[6]
        categoria = usuario[7]
        descricao_da_causa = usuario[8]
        cep = usuario[9]
        chave_pix = usuario[10]
        num_agencia = usuario[11]
        num_conta = usuario[12]
        nome_banco = usuario[13]
        endereco = usuario[14]
        complemento = usuario[15]
        nome_resp = usuario[16]
        telefone = usuario[17]
        site_url = usuario[18]
        facebook = usuario[19]
        instagram = usuario[20]

        usuarios_dic.append({
            'id_usuario': id_usuario,
            'nome': nome,
            'e_mail': e_mail,
            'senha': senha,
            'tipo': tipo,
            'ativo': ativo,
            'cnpj': cnpj,
            'categoria': categoria,
            'descricao_da_causa': descricao_da_causa,
            'cep': cep,
            'chave_pix': chave_pix,
            'num_agencia': num_agencia,
            'num_conta': num_conta,
            'nome_banco': nome_banco,
            'endereco': endereco,
            'complemento': complemento,
            'nome_resp': nome_resp,
            'telefone': telefone,
            'site_url': site_url,
            'facebook': facebook,
            'instagram': instagram
        })


    if usuarios_dic:
        return jsonify(mensagem='Registro de Cadastro de Usuários', usuarios=usuarios_dic)
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
    endereco = data.get('endereco')
    complemento = data.get('complemento')
    nome_resp = data.get('nome_resp')
    telefone = data.get('telefone')
    site_url = data.get('site_url')
    facebook = data.get('facebook')
    instagram = data.get('instagram')
    tipo_usuario = int(data.get('tipo'))

    if not validar_senha(senha):
        return jsonify({"error": 'A sua senha precisa ter pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula, um número e um caractere especial.'}), 401

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
        cursor.execute("INSERT INTO USUARIO(NOME, E_MAIL, SENHA, CNPJ, CATEGORIA, DESCRICAO_DA_CAUSA, CEP, CHAVE_PIX, NUM_AGENCIA, NUM_CONTA, NOME_BANCO, ATIVO, TIPO, ENDERECO, COMPLEMENTO, NOME_RESP, TELEFONE, SITE_URL, FACEBOOK, INSTAGRAM) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (nome, e_mail, senha, cnpj, categoria, descricao_da_causa, cep, chave_pix, num_agencia, num_conta, nome_banco, 1, 2, endereco, complemento, nome_resp, telefone, site_url, facebook, instagram))
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
                'nome_banco': nome_banco,
                'endereco': endereco,
                'complemento': complemento,
                'nome_resp': nome_resp,
                'telefone': telefone,
                'site_url': site_url,
                'facebook': facebook,
                'instagram': instagram
            }
        })
    elif tipo_usuario == 1:
        cursor.execute("INSERT INTO USUARIO(NOME, E_MAIL, SENHA, tipo, ativo) VALUES (?, ?, ?, ?, ?)",
                   (nome, e_mail, senha, 1, 1))
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
    else:
        return jsonify({
            'error': "Tipo Selecionado Inválido!"
        })


@app.route('/cadastro/<int:id>', methods=['PUT'])
def cadastro_put(id):
    cripto = 0
    tipo_usuario = request.args.get('tipo', type=int) # Essa linha utiliza 'request.args.get' para adquirir o valor do tipo armazenado no banco de dados, vimos sobre esse código no site: https://stackoverflow.com/questions/34671217/in-flask-what-is-request-args-and-how-is-it-used
    cursor = con.cursor()
    cursor.execute("select id_usuario, nome, e_mail, senha, cnpj, categoria, descricao_da_causa, cep, chave_pix, num_agencia, num_conta, nome_banco, tipo, endereco, complemento, nome_resp, telefone, site_url, facebook, instagram, ativo from usuario WHERE id_usuario = ?", (id,))
    usuario = cursor.fetchone()

    tipo_usuario = usuario[12]
    senha_armazenada = usuario[3]
    e_mail_armazenado = usuario[2]
    nome_armazenado = usuario[1]
    cnpj_armazenado = usuario[4]
    categoria_armazenada = usuario[5]
    descricao_armazenada = usuario[6]
    cep_armazenado = usuario[7]
    chave_pix_armazenado = usuario[8]
    num_agencia_armazenado = usuario[9]
    num_conta_armazenado = usuario[10]
    nome_banco_armazenado = usuario[11]
    endereco_armazenado = usuario[13]
    complemento_armazenado = usuario[14]
    nome_resp_armazenado = usuario[15]
    telefone_armazenado = usuario[16]
    site_url_armazenado = usuario[17]
    facebook_armazenado = usuario[18]
    instagram_armazenado = usuario[19]
    atividade_armazenada = usuario[20]


    if not usuario:
        cursor.close()
        return jsonify({"error": 'Registro não encontrado.'}), 401

    if tipo_usuario == 3:
        data = request.get_json()
        nome = data.get('nome')
        e_mail = data.get('e_mail')
        senha = data.get('senha')
        tipo = data.get('tipo')
        ativo = data.get('ativo')

        if senha is None:
            cripto = 1
            senha = senha_armazenada

        cursor = con.cursor()

        if e_mail_armazenado != e_mail:
            cursor.execute("SELECT 1 FROM usuario WHERE E_MAIL = ?", (e_mail,))
            if cursor.fetchone():
                return jsonify({"error": "E-mail já cadastrado!"}), 400

        if senha_armazenada != senha:
            if not validar_senha(senha):
                return jsonify({"error": 'A sua senha precisa ter pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula, um número e um caractere especial.'}), 401

        if senha is not None and cripto != 1:
            senha = generate_password_hash(senha).decode('utf-8')

        cursor.execute("UPDATE usuario SET NOME = ?, E_MAIL = ?, senha = ?, TIPO = ?, ATIVO = ? WHERE ID_USUARIO = ?",
                       (nome, e_mail, senha,  tipo, ativo, id))
        con.commit()
        cursor.close()

        return jsonify({
            'message': "Cadastro atualizado com sucesso!",
            'usuario': {
                'id_usuario': id,
                'nome': nome,
                'e_mail': e_mail,
                'senha': senha,
                'tipo': tipo,
                'ativo': ativo
            }
        }),200

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
        tipo = data.get('tipo')
        ativo = data.get('ativo')


        if nome is None:
            nome = nome_armazenado
        if e_mail is None:
            e_mail = e_mail_armazenado
        if senha is None:
            senha = senha_armazenada
        if cnpj is None:
            cnpj = cnpj_armazenado
        if categoria is None:
            categoria = categoria_armazenada
        if descricao_da_causa is None:
            descricao_da_causa = descricao_armazenada
        if cep is None:
            cep = cep_armazenado
        if chave_pix is None:
            chave_pix = chave_pix_armazenado
        if num_agencia is None:
            num_agencia = num_agencia_armazenado
        if num_conta is None:
            num_conta = num_conta_armazenado
        if nome_banco is None:
            nome_banco = nome_banco_armazenado
        if endereco is None:
            endereco = endereco_armazenado
        if complemento is None:
            complemento = complemento_armazenado
        if nome_resp is None:
            nome_resp = nome_resp_armazenado
        if telefone is None:
            telefone = telefone_armazenado
        if site_url is None:
            site_url = site_url_armazenado
        if facebook is None:
            facebook = facebook_armazenado
        if instagram is None:
            instagram = instagram_armazenado
        if tipo is None:
            tipo = tipo_usuario
        if ativo is None:
            ativo = atividade_armazenada


        cursor = con.cursor()

        cursor.execute("SELECT 1 FROM usuario WHERE E_MAIL = ?", (e_mail,))

        if e_mail_armazenado != e_mail:
            cursor.execute("SELECT 1 FROM usuario WHERE E_MAIL = ?", (e_mail,))
            if cursor.fetchone():
                return jsonify({"error": "E-mail já cadastrado!"}), 400

        if senha_armazenada != senha:
            if not validar_senha(senha):
                return jsonify({"error": 'A sua senha precisa ter pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula, um número e um caractere especial.'}), 401

            senha = generate_password_hash(senha).decode('utf-8')

        cursor.execute("UPDATE usuario SET NOME = ?, E_MAIL = ?, SENHA = ?, CNPJ = ?, CATEGORIA = ?, DESCRICAO_DA_CAUSA = ?, CEP = ?, CHAVE_PIX = ?, NUM_AGENCIA = ?, NUM_CONTA = ?, NOME_BANCO = ?, ENDERECO = ?, COMPLEMENTO = ?, NOME_RESP = ?, TELEFONE = ?, SITE_URL = ?, FACEBOOK = ?, INSTAGRAM = ?, TIPO = ?, ATIVO = ? WHERE ID_USUARIO = ?",
                       (nome, e_mail, senha, cnpj, categoria, descricao_da_causa, cep, chave_pix, num_agencia, num_conta, nome_banco, endereco, complemento, nome_resp, telefone, site_url, facebook, instagram, tipo, ativo, id))
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
                'instagram': instagram,
                'tipo': tipo,
                'ativo': ativo
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

    print(0)

    # Verifique se login_data é None antes de acessar os dados
    if login_data is None:
        cursor.close()
        return jsonify({'error': "Credenciais não encontradas"}), 400

    print(1)
    # Se o usuário não estiver ativo
    if login_data[5] != 1:
        return jsonify({'message': "Usuário Inativo!"}), 400

    senha_hash = login_data[2]

    print(2)

    # Verifica se a senha está correta
    if check_password_hash(senha_hash, senha):
        token = generate_token(login_data[4])

        print(3)

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
    print(4)

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

    imagem = request.files.get('imagem')  # Arquivo enviado

    cursor = con.cursor()

    # Verifica se já existe
    cursor.execute("SELECT 1 FROM usuario WHERE id_usuario = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Usuário não encontrado"}), 400

    # Salvar a imagem se for enviada
    imagem_path = None
    if imagem:
        nome_imagem = f"{id}.jpeg"  # Define o nome fixo com .jpeg
        pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "Livros")
        os.makedirs(pasta_destino, exist_ok=True)
        imagem_path = os.path.join(pasta_destino, nome_imagem)
        imagem.save(imagem_path)

    # VERIFICA SE A IMAGEM FOI SALVA
    return jsonify({
        'message': "Usuário cadastrado com sucesso!",
        'usuario': {
            'id': id,
            'imagem_path': imagem_path,
        }
    }), 201


@app.route('/logout', methods=['POST'])
def logout():
    response = jsonify({'message': 'Logout realizado com sucesso'}) #Exibe a mensagem de logout realizado com sucesso
    response.delete_cookie('token') #Deleta token (cookie) temporário exbido durante o login
    return response #Retorna resposta