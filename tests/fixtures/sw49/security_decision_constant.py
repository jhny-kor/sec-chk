def total(product_service, item_id, quantity):
    price = product_service.get_price(item_id)
    return quantity * price
