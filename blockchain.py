from flask import Flask, request, jsonify, render_template,redirect,url_for,session
from time import time
from flask_cors import CORS
from collections import OrderedDict
import binascii
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from uuid import uuid4
import json
import hashlib
import requests
from urllib.parse import urlparse
from flask_pymongo import PyMongo
MINING_SENDER = "The Blockchain"
MINING_REWARD = 1
MINING_DIFFICULTY = 2


class Blockchain:

	def __init__(self):
		self.transactions = []
		self.chain = []
		self.nodes = set()
		self.node_id = str(uuid4()).replace('-', '')
		# Create the genesis block
		self.create_block(0, '00')

	def register_node(self, node_url):
		parsed_url = urlparse(node_url)
		if parsed_url.netloc:
			self.nodes.add(parsed_url.netloc)
		elif parsed_url.path:
			self.nodes.add(parsed_url.path)
		else:
			raise ValueError('Invalid URL')

	def create_block(self, nonce, previous_hash):
		"""
		Add a block of transactions to the blockchain
		"""
		block = {'block_number': len(self.chain) + 1,
				 'timestamp': time(),
				 'transactions': self.transactions,
				 'nonce': nonce,
				 'previous_hash': previous_hash}

		# Reset the current list of transactions
		self.transactions = []
		self.chain.append(block)
		return block

	def create_blockp(self, nonce, previous_hash,time):
		"""
		Add a block of transactions to the blockchain
		"""
		block = {'block_number': len(self.chain) + 1,
				 'timestamp': time,
				 'transactions': self.transactions,
				 'nonce': nonce,
				 'previous_hash': previous_hash}

		# Reset the current list of transactions
		self.transactions = []
		self.chain.append(block)
		return block

	def verify_transaction_signature(self, sender_public_key, signature, transaction):
		public_key = RSA.importKey(binascii.unhexlify(sender_public_key))
		verifier = PKCS1_v1_5.new(public_key)
		h = SHA.new(str(transaction).encode('utf8'))
		try:
			verifier.verify(h, binascii.unhexlify(signature))
			return True
		except ValueError:
			return False

	@staticmethod
	def valid_proof(transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
		guess = (str(transactions) + str(last_hash) + str(nonce)).encode('utf8')
		h = hashlib.new('sha256')
		h.update(guess)
		guess_hash = h.hexdigest()
		return guess_hash[:difficulty] == '0' * difficulty

	def proof_of_work(self):
		last_block = self.chain[-1]
		last_hash = self.hash(last_block)
		nonce = 0
		while self.valid_proof(self.transactions, last_hash, nonce) is False:
			nonce += 1

		return nonce

	@staticmethod
	def hash(block):
		# We must to ensure that the Dictionary is ordered, otherwise we'll get inconsistent hashes
		block_string = json.dumps(block, sort_keys=True).encode('utf8')
		h = hashlib.new('sha256')
		h.update(block_string)
		return h.hexdigest()

	def resolve_conflicts(self):
		neighbours = self.nodes
		new_chain = None

		max_length = len(self.chain)
		for node in neighbours:
			response = requests.get('http://' + node + '/chain')
			if response.status_code == 200:
				length = response.json()['length']
				chain = response.json()['chain']

				if length > max_length and self.valid_chain(chain):
					max_length = length
					new_chain = chain

		if new_chain:
			self.chain = new_chain
			return True

		return False

	def valid_chain(self, chain):
		last_block = chain[0]
		current_index = 1

		while current_index < len(chain):
			block = chain[current_index]
			if block['previous_hash'] != self.hash(last_block):
				return False

			transactions = block['transactions'][:-1]
			transaction_elements = ['sender_public_key', 'recipient_public_key', 'amount']
			transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in
							transactions]

			if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
				return False

			last_block = block
			current_index += 1

		return True

	def submit_transaction(self, sender_public_key, recipient_public_key, signature, amount):
		transaction = {
			'sender_public_key': sender_public_key,
			'recipient_public_key': recipient_public_key,
			'amount': amount
		}

		# Reward for mining a block
		if sender_public_key == MINING_SENDER:
			self.transactions.append(transaction)
			return len(self.chain) + 1
		else:
			# Transaction from wallet to another wallet
			signature_verification = self.verify_transaction_signature(sender_public_key, signature, transaction)
			if signature_verification:
				self.transactions.append(transaction)
				return len(self.chain) + 1
			else:
				return False


# Instantiate the Blockchain
blockchain = Blockchain()

# Instantiate the Node
app = Flask(__name__)
CORS(app)
app.config['MONGO_DBNAME'] = 'restdb'
app.config['MONGO_URI'] ="mongodb+srv://Tanesh:953217Smh@cluster0-elkna.mongodb.net/test?retryWrites=true&w=majority"
mysql = PyMongo(app)
app.secret_key="secret_key"
@app.route('/')
def index():
	rp1=mysql.db.last_response.find({'message':'New block created'})
	for rp in rp1:
		for r in range(len(list(rp['transactions']))):
			if rp['transactions'][r]['sender_public_key']!="The Blockchain":
				nonce = blockchain.proof_of_work()
				tim=mysql.db.data1.find_one({'sender_public_key':rp['transactions'][r]['sender_public_key'],'recipient_public_key':rp['transactions'][r]['recipient_public_key'],'amount':rp['transactions'][r]['amount']})
				time=tim['time']
				pri = mysql.db.publickey.find_one({'publickey':rp['transactions'][r]['sender_public_key']})
				private_key = RSA.importKey(binascii.unhexlify(pri['privatekey']))
				signer = PKCS1_v1_5.new(private_key)
				dic = {'sender_public_key':rp['transactions'][r]['sender_public_key'],'recipient_public_key':rp['transactions'][r]['recipient_public_key'],'amount':rp['transactions'][r]['amount']}
				h = SHA.new(str(dic).encode('utf8'))
				trans=blockchain.submit_transaction(sender_public_key=rp['transactions'][r]['sender_public_key'],recipient_public_key=rp['transactions'][r]['recipient_public_key'],signature=binascii.hexlify(signer.sign(h)).decode('ascii'),amount=rp['transactions'][r]['amount'])
				last_block=blockchain.chain[-1]
				previous_hash = blockchain.hash(last_block)
				blockchain.create_blockp(nonce,previous_hash,time)
	return render_template('./in.html')

@app.route('/main',methods=['POST'])
def main():
	if request.form['user']=='DrCare' and request.form['pas']=='404 Not Found':
		session['logged']=True
		return render_template('./index.html')
	return redirect(url_for('index'))


@app.route('/configure')
def configure():
	return render_template('./configure.html')


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
	transactions = blockchain.transactions
	response = {'transactions': transactions}
	tran = mysql.db.response.find()
	for t in tran:
		mysql.db.response.update_one({'transactions':t['transactions']},{'$set':response})
	return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def get_chain():
	response={'chain':blockchain.chain,'length':len(blockchain.chain)}
	print('get_chain response1:- \n',str(response))
	return jsonify(response),200


@app.route('/mine', methods=['GET'])
def mine():
	# We run the proof of work algorithm
	nonce = blockchain.proof_of_work()

	blockchain.submit_transaction(sender_public_key=MINING_SENDER,
								  recipient_public_key=blockchain.node_id,
								  signature='',
								  amount=MINING_REWARD)

	last_block = blockchain.chain[-1]
	previous_hash = blockchain.hash(last_block)
	block = blockchain.create_block(nonce, previous_hash)
	f=dict(mysql.db.last_response.find_one({'message':'New block created'}))
	response = {
		'message': 'New block created',
		'block_number': f['block_number']+1,
		'transactions': f['transactions'],
		'nonce': f['nonce'],
		'previous_hash': f['previous_hash'],
	}
	for i in range(len(list(block['transactions']))-1):
		f['transactions'].append(block['transactions'][i])
		f['block_number']=block['block_number']
		f['nonce']=block['nonce']
		f['previous_hash']=block['previous_hash']
	r = mysql.db.response.find()
	sender_public_key=""
	recipient_public_key=""
	amount=""
	for resp in r:
		for j in range(len(list(resp['transactions']))):
			sender_public_key = resp['transactions'][j]['sender_public_key']
			recipient_public_key = resp['transactions'][j]['recipient_public_key']
			amount = resp["transactions"][j]['amount']
			print('\n\n\ncurrent Mine Data:- \n',sender_public_key,recipient_public_key,amount)
			mysql.db.data1.insert_one({'sender_public_key':sender_public_key,'recipient_public_key':recipient_public_key,'amount':amount,'time':time()})
	mysql.db.last_response.update_one({'message':'New block created'},{"$set":f})
	print(response)
	return jsonify(response),200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
	values = request.form
	required = ['confirmation_sender_public_key', 'confirmation_recipient_public_key', 'transaction_signature',
				'confirmation_amount']
	if not all(k in values for k in required):
		return 'Missing values', 400

	transaction_results = blockchain.submit_transaction(values['confirmation_sender_public_key'],
														values['confirmation_recipient_public_key'],
														values['transaction_signature'],
														values['confirmation_amount'])
	if transaction_results == False:
		response = {'message': 'Invalid transaction/signature'}
		return jsonify(response), 406
	else:
		response = {'message': 'Transaction will be added to the Block ' + str(transaction_results)}
		print('new_transactions response1:- \n',str(response))
		return jsonify(response),200


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
	nodes = list(blockchain.nodes)
	response = {'nodes': nodes}
	print('get_nodes response2:- \n',str(response))
	return jsonify(response), 200


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
	replaced = blockchain.resolve_conflicts()

	if replaced:
		response = {
			'message': 'Our chain was replaced',
			'new_chain': blockchain.chain
		}
	else:
		response = {
			'message': 'Our chain is authoritative',
			'chain': blockchain.chain
		}
	print('consensus response2:- \n',str(response))
	return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_node():
	values = request.form
	# 127.0.0.1:5002,127.0.0.1:5003, 127.0.0.1:5004
	nodes = values.get('nodes').replace(' ', '').split(',')

	if nodes is None:
		return 'Error: Please supply a valid list of nodes', 400

	for node in nodes:
		blockchain.register_node(node)

	response = {
		'message': 'Nodes have been added',
		'total_nodes': [node for node in blockchain.nodes]
	}
	return jsonify(response), 200
