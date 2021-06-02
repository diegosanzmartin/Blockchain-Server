# PRÁCTICA BLOCKCHAIN - SISTEMAS INTELIGENTES/SOLUCIONES INTELIGENTES - UAH
# Pilar Martin Martin- 20/21

# Importamos la función o método sha256 para poder calcular hashes.
# Recordamos que la función hash que usaba Bitcoin era SHA-256
from hashlib import sha256

# Importamos JSON.
# Nos permite manejar datos en formato JSON. 
# Esta forma de describir datos deriva de JavaScript: JSON = JavaScript Object Notation.
# Los datos que le pasamos a las peticiones que hacemos con Postman están en este formato.
import json

# Importamos TIME. 
# Time nos permite obtener el instante de tiempo actual 
# como la cantidad de segundos que han pasado desde el Epoch de UNIX (el 1/1/1970). 
# Lo empleamos para poner marcas de tiempo a las peticiones que hacemos.
import time

# Importamos FLASH. 
# Flask permite montar un servidor web de manera sencilla.
# Podemos manejar aplicaciones a través de una interfaz que usa la tecnología HTTP que está tan probada y desplegada.
# 
# En esta práctica, las peticiones HTTP no se hacen través del navegador 
# emplearemos Postman para poder adjuntar datos a esas peticiones de manera más sencilla.
# 
# No usamos un servidor web tradicional, sino que queremos implementar una API REST.
# Esto es, al hacer peticiones a una URL determinada provocaremos que el servidor lleve a cabo una serie de acciones.
# No queremos que se nos entregue una simple página y ya está.
# Es una forma sencilla de interconectar aplicaciones que se ejecutan en varias plataformas.
# 
# Un ejemplo: para subir datos a ThingSpeak (plataforma IoT de Matlab) 
# se usa la API REST que nos proporcionaba el propio ThingSpeak para subir los datos.
# Por eso podemos trabajar con un programa en Python o con lo que queramos.
#
# Para poder emplear Flask debemos importar todo esto...
from flask import Flask, jsonify, request

# Importamos REQUESTS
# Nos permite hacer peticiones HTTP a través de un interfaz súper sencillo
# En el código, se emplea para hacer peticiones tanto el método HTTP GET como con POST 
# para interactuar con la propia API REST que implementa el servidor web de Flask.
import requests

# Clase BLOCK:
# Esta clase representa a uno de los muchos bloques que componen el blockchain que estamos construyendo.
class Block:
    #
    # Esta función es el constructor de cada bloque: se crea tan pronto como se instancia un objeto de la clase.
    # Se inicializan una serie de atributos.
    # El parámetro 'nonce' vale por defecto 0 si no se explicita en la llamada al constructor.
    def __init__(self, index, transactions, timestamp, previous_hash, nonce = 0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        
    # Función compute_hash: Esta función devuelve el hash SHA-256 del bloque. 
    def compute_hash(self):
        """
        A function that return the hash of the block contents.
        """
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()
    # Para representar los bloques vamos a emplear el formato JSON.
    # La función json.dumps() devuelve una cadena JSON generada a partir del diccionario que le pasemos.
    # En este caso, la representación en JSON tendrá los miembros ordenados tal
    # y como explicitamos con el argumento sort_keys. 
    # En definitiva, esta función devuelve una representación del objeto como una cadena,
    # algo que podemos hashear sin problema.
    #
    # Todos los objetos en python tienen un atributo que se genera automáticamente: self.__dict__.
    # Éste contiene una representación de los atributos de un objeto en forma de diccionario. 
    # Este tipo de datos es muy común en Pyhton. Podemos pensar en él como una lista que se indexa con
    # cadenas y cuyos valores pueden ser de cualquier tipo. 
    # Los posibles índices se denominan llaves (keys).
    # Los diccionarios son, en definitiva, una serie de pares clave<-->valor.
    # En nuestro caso, self.__dict__ tiene como clave los nombres de los atributos. 
    # Ejemplos para esta clase son 'index', 'transactions', 'nonce'... Los valores serán los que correspondan.
    # En definitiva, block_string será una cadena en formato JSON que representa todos los contenidos del bloque.
    # Para probar todo esto puedes ejecutar el intérprete de python3 escribiendo simplemente
    # 'python3' en un terminal y la siguiente clase:
        # class foo:
        # def __init(self):
        #     self.x = 1
        #     self.y = 'Hey!'
    # Después ejecuta foo().__dict__ para instanciar la clase y ver el valor del diccionario self.__dict__.
    # Deberías obtener que self.dict = {'x': 1, 'y': 'Hey!'}
    #
    # Tras representar el objeto como una cadena solo hay que hashearlo. 
    # Para ello primero tenemos que convertir la cadena a un objeto de tipo bytes. 
    # Este objeto contiene los bytes (caracteres) que componen la cadena uno detrás del otro. 
    # Podemos pensar en él como en una cadena de C pura y dura: una serie de bytes; nada más.
    # Este objeto es el que se suele pasar a funciones que trabajan a nivel de byte como los hashes o
    # a sockets que empaquetan bytes para ser enviados por la red, no entienden nada de cadenas... 
    # Solo tenemos que instanciar un objeto de tipo sha256() y llamar al método hexdigest() para devolver el hash.
    # Este método devuelve una cadena en vez de un objeto de tipo bytes, cosa que hace más sencillo trabajar con él.
    #
    # Señalamos que se podría haber condensado todo en una línea de la siguiente manera:
    # eturn sha256(json.dumps(self.__dict__, sort_keys = True).encode()).hexdigest()


# CLASE BLOCKCHAIN: 
# Esta clase representa a todo el blockchain. Como veremos, ésto no es más que una lista de objetos tip
class Blockchain:
    # Con este parámetroo definimos el número de 0s que debe haber al principio del hash calculado. Cuanto mayor
    # sea el número más difícil será resolver el prooblema y más tiempo tendremos que estar calculando todo...
    difficulty = 4

    # Esta función es el constructor de la cadena completa. 
    # Se inicializan dos listas vacías y se crea el genesis (bloque primero)
    # 1. self.unconfirmed_transactions: Contiene las transacciones que todavía no ha resuelto nadie.
    # 2. self.chain: Contiene el  blockchain con todas las transacciones ya validadas.
    # 3. función create_genesis_block: Crea el bloque génesis automáticamente para evitar tener que hacerlo explícitamente.
    def __init__(self):
    	self.unconfirmed_transactions = []
    	self.chain = []
    	self.create_genesis_block()
    	   
    # Función create_genesis_block: Esta función genera el primer bloque de todos. Instanciamos la clase Block con:
    # 1. una lista sin transacciones,
    # 2. un hash anterior de 0, índice 0 y timestamp (marca de tiempo) 0.
    # 3. el nonce que se emplea es el que estaba por defecto en el constructor de la clase Block, 0.
    #
    # Tras crear el bloque le incorporamos el miembro 'hash' que contiene el propio hash del bloque y lo
    # añadimos a la lista 'chain' que es un atributo de esta misma clase. 
    # Para ello empleamos el método append() de las listas que añade elementos al final. 
    # Así vamos generando un blockchain ordenado.
    def create_genesis_block(self):
    	"""
    	A function to generate genesis block and appends it to
    	the chain. The block has index 0, previous_hash as 0, and
    	a valid hash.
    	"""
    	genesis_block = Block(0, [], 0, "0")
    	genesis_block.hash = genesis_block.compute_hash()
    	self.chain.append(genesis_block)
        
    @property
    def last_block(self):
        return self.chain[-1]
    # Estas 3 líneas de arriba es lo que en Python se llaman decoradores (decorators en inglés).
    # Éstos se utilizan para pasar la función que tienen debajo a la función indicada por el decorador 
    # y luego devolver la salida de esto último. 
    # Así puesto parece una locura, pero con un ejemplo es todo más asequible. 
    # Esta sintaxis que vemos equivale a:
    #
        # def last_block(self):
        #   return self.chain[-1]
        #   last_block = property(last_block)
    #
    # Lo que estamos haciendo a través de la función property() que pertenece al propio núcleo de Python
    # es definir un getter para el atributo self.last_block. 
    # Por tanto, si en algún lugar del código referenciamos al atributo last_block se llamará a la función last_block() 
    # para devolver el último bloque de la cadena.
    # Resulta ser bastante estándar trabajar con este tipo de expresión...
    #
    # Para poder acceder al último elemento de la lista usamos los índices negativos que nos permite python. 
    # Vemos que: self.chain[-1] = self.chain[len(chain) - 1]. Los índices negativos son de uso muy común...
   

    # Función add_block: Esta función verifica el bloque y lo añadirá a la cadena. Para ello comprueba:
    # 1. si el "proof" es valido: que el valor que se ha encontrado tenga el número de ceros requeridos
    #    Esta comprobación se hace utilizando la función is_valid_proof()
    # 2. Si previous_hash (hash del bloque anterior escrito en este bloque) es igual al hash del último bloque de la lista self.chain. 
    # En caso de que no se cumpla alguna de las 2 condiciones
    # la función simplemente sale devolviendo False para indicar que el bloque no era válido...
    #
    # Si el bloque es válido se crea una nueva transacción que se define como un diccionario. 
    # Se genera la transacción recompensa: reward_trx
    # Y se incorpora al bloque utilizando la función de la clase Blockchain: add_new_transaction() 
    # Más tarde, se le añade el hash correcto del propio bloque al bloque que se ha incorporado
    # (recordemos que hemos comprobado que era correctoo antes), 
    # se añade este bloque a la cadena
    # se devuelve True para indicar que todo ha ido bien. 
    def add_block(self, block, proof):
        """
        A function that adds the block to the chain after verification.
        Verification includes:
        * Checking if the proof is valid.
        * The previous_hash referred in the block and the hash of latest block
          in the chain match.
        """
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            return False

        if not Blockchain.is_valid_proof(block, proof):
            return False


        # Recompensa
        reward_trx = {
            'Sender': "Blockchain Master",
            'Recipient': "Node_Identifier",
            'Amount': 1,
            'Timestamp': time.time(),
        }
        
        blockchain.add_new_transaction(reward_trx)
        

        block.hash = proof
        self.chain.append(block)
        return True

  
    # Función proof_of_work: Esta función busca diferentes valores of nonce para obtener el hash
    # que satisface el criterio de dificultad impuesto.
    # La función se encarga de, dado un bloque, intentar resolver el acertijo que se resuelve al
    # encontrar un valor para el atributo 'nonce' de la clase Block tal que el hash del bloque
    # comienza con tantos 0s como definamos en el método de la clase 'difficulty'. Para ello
    # simplemente comienza probando con 0 y va incrementando el 'nonce' de 1 en 1 hasta que acierta.
    # Cuando logra el resultado devuelve el hash que ha calculado y que tiene los 0s necesarios
    # Para comprobar ésto se utiliza el método starts_with() de las cadenas que resulta ser muy útil .
    # 
    # Como ya se ha explicado anteriormente. Esta definición equivale a:
        # def proof_of_work():
        #     ..
        #     proof_of_work = staticmethod(proof_of_work)
    #
    # La función staticmethod() del núcleo de Python convierte el argumento que le pasemos en una función estática de la clase. 
    # Este método o función no recibirá una copia del objeto a traves del que lo llamamos
    # como sí pasa con los demás (de ahí el parámetro self que ponemos una y otra vez) sino que
    # simplemente es una función que está accesible a través de la propia clase, no hay que instanciar
    # un objeto para poder llamarla. De cara a la práctica es una función.
    #
    @staticmethod
    def proof_of_work(block):
        """
        Function that tries different values of nonce to get a hash
        that satisfies our difficulty criteria.
        """
        block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    # Función add_new_transaction: Esta función añade una transacción a la lista self.unconfirmed_transactions.
    # hasta que se añada a uno de los bloques y se compruebe.
    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    # Función is_valid_proof: Esta función se encarga de comprobar que el bloque es válido 
    # Para ello comprueba
    # 1. que el hash del bloque que se pasa como parámetro ('block_hash', que es una cadena), comience con tantos 0s como sea necesario
    # 2. que este hash sea en efecto el mismo que el del bloque, cosa de la que se cerciora calculando el hash ella misma. 
    # La función devuelve True si se cumplen ambas condiciones y False en caso contrario.
    @classmethod
    def is_valid_proof(cls, block, block_hash):
        """
        Check if block_hash is valid and satisfies
        the difficulty criteria.
        """
        return (block_hash.startswith('0' * Blockchain.difficulty) and
                block_hash == block.compute_hash())

    # En este caso empleamos el decorador @classmethod lo que convierte al método is_valid_proof() en un método
    # de la clase de manera que se recibe la clase como el primer argumento implícito (cls) en vez de la instancia
    # (self) a la que estamos acostumbrados. Tal y como ocurría antes, la sintaxis que aparece es equivalente a:
        # def check_chain_validity():
            # ...
            # check_chain_validity = classmethod(check_chain_validity)
    # Con ello podemos acceder a métodos de la clase como is_valid_proof() en este caso.
    #
    #
    # Función check_chain_validity: Esta función se encarga de comprobar la validez de todo el blockchain. 
    # Para ello establece unos parámetros iniciales que permiten comprobar el bloque Génesis 
    # y después va leyendo cada uno de los bloques actualizando los valores con los que comparar
    # Si llega un momento en el que hay dos bloques consecutivos cuyos hashes no estén correctamente enlazados,
    # esto es, que el hash del primer bloque NO sea el previous_hash del segundo o que el hash actual de un bloque no cumpla
    # el requsito de dificultad se devuelve False. Si todo el blockchain está bien se devuelve True.
    #
    # Cabe destacar que como el hash de un bloque se calcula sin tener en cuenta su propio hash, 
    # al calcular un hash no existe el atributo self.hash del bloque, debemos borrarlo antes de llamar a is_valid_proof() 
    # De lo contrario ningún bloque será válido... Este miembro se borra a través de la función delattr().

    @classmethod
    def check_chain_validity(cls, chain):
        result = True
        previous_hash = "0"

        for block in chain:
            block_hash = block.hash
            # remove the hash field to recompute the hash again
            # using `compute_hash` method.
            delattr(block, "hash")

            if not cls.is_valid_proof(block, block_hash) or \
                    previous_hash != block.previous_hash:
                result = False
                break

            block.hash, previous_hash = block_hash, block_hash

        return result
    
    # Función mine: Esta función o método se llama cuando tenemos una serie de transacciones no confirmadas que queremos añadir al blockchain.
    # Lo primero es comprobar que la lista de transacciones pendientes no esta vacía o de lo contrario devolvemos False.
    # Después cogemos el último bloque y generamos uno nuevo que contendrá las transacciones que vamos a validar.
    # Fijémonos en la llamada al constructor, donde se incrementa el índice respecto al del último bloque,
    # el previous_hash será el del último bloque y donde el tiempo actual se obtiene
    # con time.time() y será un enetero. Las transacciones son la lista que queremos validar.
    #
    # Tras generar el bloque comenzamos a resolver el acertijo hasta encontrar el nonce que da el hash con la dificultad requerida.
    # Cuando lo encontramos intentamos añadir el bloque al blockchain donde se comprobará que todo está correcto. 
    # solo queda limpiar las transacciones que ya hemos añadido y devolver True para indicar que todo ha salido correctamente. 
    # Esta clase es así de escueta porque emplea todos los métodos que hemos ido definiendoo más arriba.
    def mine(self):
        """
        This function serves as an interface to add the pending
        transactions to the blockchain by adding them to the block
        and figuring out Proof Of Work.
        """
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)

        proof = self.proof_of_work(new_block)
        
        self.add_block(new_block, proof)

        self.unconfirmed_transactions = []

        return True

#//// Parte 1 ////////////////////////////////////////////////////////////////////////////////////////////////////

    def validate(self):
        print(self.last_block)



# Instanciamos el servidor de Flask con el valor de __name__, una vriable interna de Python
app = Flask(__name__)

# Inicializamos la cadena blockchain
# the node's copy of blockchain
blockchain = Blockchain()



#blockchain.create_genesis_block()

# Las direcciones de los demás peers (mineros) de la red. Por ahora es un conjunto vacío. 
# La ventaja de éste es que nos garantiza que no habrá direcciones repetidas...
# the address to other participating members of the network
peers = set()


# Trata de recuperar la función shutdown() de werkzeug. Werkzeug es la del Web Server Gateway Interface (WSGI). 
# Las peticiones HTTP se hacen a un servidor que se encarga de manejar todos los sockets y conexiones. 
# Este servidor web le pasa las peticiones al WSGI, en este caso werkzeug y éste a la aplicación de Flask propiamente dicha.
# No obstante, la llamada a app.run() levanta un servidor automáticamente y configura todo para que Flask sea quien responda a las peticiones. 
# Si quisiéramos podríamos montar todo esto con un servidor web como Nginx o Apache y configurar todo para trabajar de la misma manera. 
# No obstante, optamos por usar un sistema sencillo. 
# En definitiva, lo que nos importa a nosotros es que vamos a levantar un servidor que responde a peticiones.
#
# Esta función recupera el servidor de depuración, que en realidad forma parte de Werkzeug y lo apaga. 
# Si no estamos usando Werkzeug simplemente lanzamos una excepción que será manejada.
# Si el entorno está en efecto basado en Werkzeug apagamos el servidor con la llamada a func() y listo.
def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

# La sintaxis que aparece más abajo equivale a:
    # def shutdown():
    #   foo
    # shutdown = app.route(shutdown, '/shutdown', methods = ['POST'])
# Con el método route() del objeto app registramos la URL que acaba en '/shutdown' para que al hacer una
# petición HTTP POST a la misma se ejecute la función shutdown(). Éste es el funcionamiento básico de una
# API REST: hacemos peticiones a URL concretas para llamar a funciones. Teniendo en cuenta que los accesos
# serán desde nuestra máquina si hacemos una petición POST a 'http://127.0.0.1:8000/shutdown' se ejecutará
# shutdown(). Estamos teniendo en cuenta que se lanza el servidor en el puerto 8000 que es el que se usa
# por defecto tal y como veremos al final del código. Recordamos que la IP 127.0.0.1 es localhost, es decir
# nuestra propia máquina.
#
# Resumiendo, en esta función llamamos a shutdown_server() para apagar todo.
@app.route('/shutdown', methods=['POST'])
def shutdown():
    shutdown_server()
    return 'Server shutting down...'


# Cuando hagamos peticiones POST a 'http://127.0.0.1:8000/new_transaction' se ejecutará new_transaction().
# Junto a la petición POST debemos adjuntar un objeto JSON que recuperamos a través de request.get_json()
# y que debe contener al menos los campos 'Recipient', 'Sender' y 'Amount'. Si no tiene alguno de ellos
# se responderá con una 404 Not Found indicando que ha habido un error. Si la transacción es correcta
# se responderá con un 201 Created indicando que se ha llamado a add_new_transaction() con lo que se añade
# una transacción más al bloque actual. Recordamos que la marca de tiempo, el timestamp() se recupera a través
# de time.time()
#
# endpoint to submit a new transaction. This will be used by
# our application to add new data (posts) to the blockchain
@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    tx_data = request.get_json()
    required_fields = ["Recipient", "Sender", "Amount"]

    for field in required_fields:
        if not tx_data.get(field):
            return "Invalid transaction data", 404

    tx_data["timestamp"] = time.time()

    blockchain.add_new_transaction(tx_data)

    return "Success", 201

# Al hacer una petición GET a 'http://127.0.0.1:8000/chain' se devuelve un objeto JSON 
# una lista de diccionarios siendo cada diccionario la representación de un bloque.
# Para construir este objeto JSON se llama a jsonify() a la que le pasamos un
# diccionario que representa el objeto JSON a devolver. 
# Este objeto también tiene una lista con todos los peers de la red.
# El código de respuesta es un 200 OK.
#
# endpoint to return the node's copy of the chain.
# Our application will be using this endpoint to query
# all the posts to display.
@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
        
    #return json.dumps({"length": len(chain_data),
    #                   "chain": chain_data,
    #                   "peers": list(peers)}, indent=8)
    
    response = {
        "length": len(chain_data),
        "chain": chain_data,
        "peers": list(peers)
    }
    return jsonify(response), 200



# Al hacer una petición 'GET' a 'http://127.0.0.1:8000/mine' le pedimos al nodo que empiece a minar las transacciones 
# que no haya confirmado. Si existe alguna transacción por minar tratamos de ver qué nodo tiene el blockchain más largo, 
# cosa que logramos a través de la función consensus(). Si resulta que tenemos el blockchain más largo anunciamos 
# que hemos añadido un bloque para que los demás nodos actualicen sus blockchains y todo se sincronice, 
# cosa que se logra con la función announce_new_block(). 
# Devolvemos una cadena indicando el índice del último bloque minado ya sea por nosotros o por otro nodo.
#
# endpoint to request the node to mine the unconfirmed
# transactions (if any). We'll be using it to initiate
# a command to mine from our application itself.
@app.route('/mine', methods=['GET'])
def mine_unconfirmed_transactions():
    result = blockchain.mine()
    if not result:
        return "No transactions to mine"
    else:
        # Conseguimos la longitud de nuestro blockchain
        # Making sure we have the longest chain before announcing to the network
        chain_length = len(blockchain.chain)
        consensus()
        if chain_length == len(blockchain.chain):
            # Si nuestro blockchain era el más largo anunciamos que hemos añadido un bloque nuevo a los demás.
            # announce the recently mined block to the network
            announce_new_block(blockchain.last_block)
        return "Block #{} is mined.".format(blockchain.last_block.index)



# Esta función se llama internamente, no está pensada para que un usuario la llame directamente. 
# Para ello le entregamos una copia del blockchain actual. 
# Antes de registrar un nodo comprobamos que nos pase una dirección IP válida o de lo
# contrario devolvemos un código 400 Bad Request.
#
# endpoint to add new peers to the network.
@app.route('/register_node', methods=['POST'])
def register_new_peers():
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    # Añadimos el nodo a la lista
    # Add the node to the peer list
    peers.add(node_address)

    # Le pasamos el blockchain actual para que se sincronice con nosotros
    # Return the consensus blockchain to the newly registered node
    # so that he can sync
    return get_chain()


# Al hacer una petición POST a 'http://127.0.0.1:8000/register_with' debemos pasar un objeto JSON con la IP del nodo
# en el que nos queremos registrar. Automáticamente, haremos una petición a 'register_new_peers()' del nodo con el que
# nos queremos registrar. Con ello, recibiremos una copia del blockchain y tendremos la misma lista de peers que tenga
# este nodo. En definitiva, elegimos un nodo con el que sincronizarnos y lo "clonamos" para engancharnos a la red y
# empezar a intentar minar.
@app.route('/register_with', methods=['POST'])
def register_with_existing_node():
    """
    Internally calls the `register_node` endpoint to
    register current node with the node specified in the
    request, and sync the blockchain as well as peer data.
    """
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    data = {"node_address": request.host_url}
    headers = {'Content-Type': "application/json"}

    # Hacemos una petición para registrarnos con el nodo que especifiquemos al hacer la petición a '/re
    # Make a request to register with remote node and obtain information
    response = requests.post(node_address + "/register_node",
                             data=json.dumps(data), headers=headers)

    # Si nos hemos registrado correctamente
    if response.status_code == 200:
        global blockchain
        global peers
        # Actualizamos nuestra copia del blockchain y la lista de peers o nodos de la red
        # update chain and the peers
        chain_dump = response.json()['chain']
        blockchain = create_chain_from_dump(chain_dump)
        peers.update(response.json()['peers'])
         # Devolvemoos un 200 OK
        return "Registration successful", 200
    else:
        # Si ocurre algún error lo maneja la API de response
        # if something goes wrong, pass it on to the API response
        return response.content, response.status_code



# Función create_chain_from_dump: Esta función genera el blockchain a partir de la información que se nos 
# proporciona al registrarnos en la red.
# En la función iteramos sobre todos los bloques de la cadena que nos pasan y vamos
# comprobando que todos los bloques son correctos antes de añadirlos. Así podemos estar seguro de que la copia
# que hemos recibido no ha sido modificada.
def create_chain_from_dump(chain_dump):
    generated_blockchain = Blockchain()
    generated_blockchain.create_genesis_block()
    for idx, block_data in enumerate(chain_dump):
        if idx == 0:
            # Nos saltamos el bloque génesis ya que ya lo hemos creado al instanciar un bloockchain vacío.
            continue  # skip genesis block
        block = Block(block_data["index"],
                      block_data["transactions"],
                      block_data["timestamp"],
                      block_data["previous_hash"],
                      block_data["nonce"])
        proof = block_data['hash']
        # La función add_block() comprueba que el bloque sea válido antes de añadirlo. Si no se ha añadido un
        # bloque lanzamos una excepción avisando de que la cadena que hemos recibido no es correcta y ha sido
        # modificada.
        added = generated_blockchain.add_block(block, proof)
        if not added:
            raise Exception("The chain dump is tampered!!")
    # Si todo ha ido bien se devuelve la cadena construida.
    return generated_blockchain

# Cuando un nodo mina un bloque llama a los demás nodos para que lo añadan a su blockchain. Antes de hacerlo los
# demás nodos comprueban que el bloque sea correcto, respondiendo con un 201 Created. Si el bloque no "les cuadra"
# responderán con un 400 Bad Request indicando que algo ha ido mal...
#
# endpoint to add a block mined by someone else to
# the node's chain. The block is first verified by the node
# and then added to the chain.
@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    block_data = request.get_json()
    block = Block(block_data["index"],
                  block_data["transactions"],
                  block_data["timestamp"],
                  block_data["previous_hash"],
                  block_data["nonce"])

    proof = block_data['hash']
    added = blockchain.add_block(block, proof)

    if not added:
        return "The block was discarded by the node", 400

    return "Block added to the chain", 201

# Al hacer peticiones a '/pending_tx' se devuelve la lista de transacciones pendientes del nodo como
# un objeto JSON
#
# endpoint to query unconfirmed transactions
@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transactions)

#//// Parte 1 ////////////////////////////////////////////////////////////////////////////////////////////////////
@app.route('/validate_chain')
def validate_chain():
    chain = blockchain.validate()
    return "OK", 200

#////////////////////////////////////////////////////////////////////////////////////////////////////////////////

# Cuando queremos añadir un bloque al blockchain avisaremos a todos los demás nodos de la red. 
# Les haremos una petición para saber la longitud de sus cadenas. 
# Si son tan largas como la nuestra o menos entonces estamos actualizados y podemos añadir el bloque a nuestro blockchain. 
# Si alguno de los nodos dice tener una cadena más larga que la nuestra y es valida
# simplemente la copiamos en la nuestra para actualizarnos y no añadimos nada... hemos sido demasiado lentos.
def consensus():
    """
    Our naive consnsus algorithm. If a longer valid chain is
    found, our chain is replaced with it.
    """
    global blockchain

    longest_chain = None
    current_len = len(blockchain.chain)

    for node in peers:
        # Conseguimos un objeto que contiene la longitud de la cadena a través del
        # endpoint '/chain' definido en la línea 387
        response = requests.get('{}chain'.format(node))
        # Accedemos a elementos de este objeto
        length = response.json()['length']
        chain = response.json()['chain']
        if length > current_len and blockchain.check_chain_validity(chain):
            current_len = length
            longest_chain = chain

    if longest_chain:
        blockchain = longest_chain
        return True

    return False

# Función announce_new_block: Una vez que el bloque ha sido minado se lo anunciamos a cada nodo para que lo verifiquen y lo
# añadan a sus blockchains. Con eso conseguimos que todo el mundo siga sincronizado. 
# Para lograr que los demás se actualizen hacemos peticiones al endpoint '/add_block' 
def announce_new_block(block):
    """
    A function to announce to the network once a block has been mined.
    Other blocks can simply verify the proof of work and add it to their
    respective chains.
    """
    for peer in peers:
        url = "{}add_block".format(peer)
        headers = {'Content-Type': "application/json"}
        requests.post(url,
                      data=json.dumps(block.__dict__, sort_keys=True),
                      headers=headers)

# Si lanzamos la aplicación desde la terminal el intérprete de python inicializa la variable __name__ con la cadena '__main__'.
# Por lo tanto solo lanzamos el servidor si ejecutamos la aplicación explícitamente.
#
# Uncomment this line if you want to specify the port number in the code
#app.run(debug=True, port=8000)

if __name__ == '__main__':
    # Importamos ArgumentParser para facilitar la lectura de parámetros por la terminal. 
    # Lo podríamos hacer a mano con sys.argv[] que es análogo al char** argv de C pero vamos, si está hecho, 
    # pues eso que nos llevamos. Con el parámetro '-p' o '--port' especificamos
    # el puerto en el que queremos que escuche el servidor...
    from argparse import ArgumentParser
    
    # Parseamos los argumentos y leemos el puerto. Si no especificamos uno se empleará el puerto 8000 
    # y si la liamos con las opciones se imprime el mensaje 'port to listen on' para que sepamos cómo especificar las opciones.
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    # Cuando tenemos el puerto claro simplemente arrancamos el servidor de depuración que nos ofrece Werkzeug. 
    # Lo ponemos a escuchar en todas las interfaces con el coodín '0.0.0.0' que equivale al INADDR_ANY de C. 
    # Si solo vamos a usar la máquina local podemos especificar la IP '127.0.0.1' para solo aceptar las conexiones 
    # de la propia máquina local. Pero vamos, que si no queremos liarnos
    # la manta a la cabeza con esto vale. El servidor se levanta en el puerto 8000.
    app.run(host='0.0.0.0', port=port)