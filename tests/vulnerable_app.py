from flask import Flask, request

app = Flask(__name__)


@app.route("/products")
def products():

    product_id = request.args.get("id", "")

    # Error-based SQLi test endpoint
    if "'" in product_id:
        return "SQLite error: unrecognized token near SQL syntax", 500

    return f"Product ID: {product_id}", 200


@app.route("/boolean")
def boolean_test():

    product_id = request.args.get("id", "")

    # Simulate a database query:
    #
    # id=1          -> product exists
    # id=1 AND 1=1 -> TRUE -> product exists
    # id=1 AND 1=2 -> FALSE -> product does not exist

    if "AND 1=2" in product_id.upper():
        return "Product not found", 404

    return "Product found", 200


@app.route("/search")
def search():

    query = request.args.get("q", "")

    if "'" in query:
        return "PostgreSQL syntax error at or near SQLSTATE", 500

    return f"Search: {query}", 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)