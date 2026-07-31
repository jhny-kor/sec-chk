def total(request, quantity):
    price = request.args["price"]
    return quantity * price
