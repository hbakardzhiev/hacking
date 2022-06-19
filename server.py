# Flask server that responds on M1 requesting content after being DNSspoofed
from flask import Flask
app = Flask(__name__, static_url_path = "", static_folder="")


@app.route("/")
def hello():
    return app.send_static_file("google.html")

# flask run -h localhost -p 8081
if __name__ == "__main__":
    app.run(host = "0.0.0.0", port = 80)