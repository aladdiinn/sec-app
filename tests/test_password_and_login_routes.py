import unittest
import app
import database as db

class TestPasswordAndLoginRoutes(unittest.TestCase):
    def test_login_routes_mapped_to_auth_login(self):
        login_routes = {}
        for r in app.app.routes:
            path = getattr(r, "path", None)
            methods = getattr(r, "methods", set())
            if path in ["/auth/login", "/api/login", "/change-password"]:
                login_routes[path] = (r.name, methods)

        self.assertIn("/auth/login", login_routes)
        self.assertEqual(login_routes["/auth/login"][0], "auth_login")
        self.assertIn("POST", login_routes["/auth/login"][1])

        self.assertIn("/api/login", login_routes)
        self.assertEqual(login_routes["/api/login"][0], "auth_login")
        self.assertIn("POST", login_routes["/api/login"][1])

        self.assertIn("/change-password", login_routes)
        self.assertEqual(login_routes["/change-password"][0], "change_password_page")
        self.assertIn("GET", login_routes["/change-password"][1])

    def test_validate_password_strength_rules(self):
        # 1. Under 8 characters
        ok, msg = app.validate_password_strength("Short1!")
        self.assertFalse(ok)
        self.assertIn("at least 8 characters", msg)

        # 2. Missing uppercase
        ok, msg = app.validate_password_strength("lowercase123!@#")
        self.assertFalse(ok)
        self.assertIn("uppercase", msg)

        # 3. Missing lowercase
        ok, msg = app.validate_password_strength("UPPERCASE123!@#")
        self.assertFalse(ok)
        self.assertIn("lowercase", msg)

        # 4. Missing number
        ok, msg = app.validate_password_strength("NoNumbersAtAll!@#")
        self.assertFalse(ok)
        self.assertIn("number", msg)

        # 5. Missing special character
        ok, msg = app.validate_password_strength("Adminsecure2026")
        self.assertFalse(ok)
        self.assertIn("special character", msg)

        # 6. Valid strong password
        ok, msg = app.validate_password_strength("Admin@secure2026!")
        self.assertTrue(ok)
        self.assertEqual(msg, "Strong password")

        ok2, msg2 = app.validate_password_strength("BSmart#2026Secure")
        self.assertTrue(ok2)

    def test_database_password_length_guard(self):
        # Database functions must reject passwords under 8 characters
        with self.assertRaises(ValueError):
            db.create_user("test_user", "test@example.com", "short")

        with self.assertRaises(ValueError):
            db.change_user_password(1, "short")

if __name__ == '__main__':
    unittest.main()
