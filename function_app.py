import azure.functions as func
from auth.login import login_bp
from auth.signup import signup_bp
from Routes.UserRoutes.order import order_bp
from Routes.AdminRoutes.get_users import get_users_bp
from Routes.AdminRoutes.get_orders import get_orders_bp
from Routes.AdminRoutes.change_order_status import change_order_status_bp
from Routes.UserRoutes.MyOrders import get_myorder_bp
from Routes.AdminRoutes.create_product import create_product_bp
from Routes.AdminRoutes.delete_product import delete_product_bp
from auth.google_login import google_login_bp
from Routes.AdminRoutes.update_product import update_product_bp
from Routes.AdminRoutes.get_products import get_products_bp

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

## Authentication Functions
app.register_functions(update_product_bp)
app.register_functions(get_products_bp)
app.register_functions(delete_product_bp)
app.register_functions(create_product_bp)
app.register_functions(change_order_status_bp)
app.register_functions(get_orders_bp)
app.register_functions(get_users_bp)
app.register_functions(order_bp)
app.register_functions(signup_bp)
app.register_functions(login_bp)
app.register_functions(google_login_bp)
app.register_functions(get_myorder_bp)

