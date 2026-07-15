from flask import Flask, request
#the uses of the Flask framework is to create a server that can use all the http methods that are in the traffic.py file 
  
app = Flask(__name__)

@app.route("/", methods=["GET"])
def get():
    return "GET OK", 200

@app.route("/", methods=["POST"])
def post():
    print(request.form)
    return "POST OK", 200

@app.route("/", methods=["PUT"])
def put():
    return "PUT OK", 200

@app.route("/", methods=["PATCH"])
def patch():
    return "PATCH OK", 200

@app.route("/", methods=["DELETE"])
def delete():
    return "DELETE OK", 200

app.run(host="0.0.0.0", port=8080)   #we used flask as a server to handle the http requests to make the traffich realistic 