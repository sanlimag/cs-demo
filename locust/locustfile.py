import time, random
from locust import HttpUser, task, between
from random import randint

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
]

class QuickstartUser(HttpUser):
    wait_time = between(1, 10)

    def on_start(self):
        self.headers = {"User-Agent": USER_AGENTS[random.randint(0,len(USER_AGENTS)-1)]}
        self.client.headers = self.headers
#        # Create test user
#        self.client.get("/register")
#        response = self.client.post("/register", {"username": "test", "email": "test@mail.com", "password": "test", "register": ""})
#        print(f"###### Create Test User request...")
#        print("Request url: {response.request.url}")
#        print(f"Request headers: {response.request.headers}")
#        print(f"Request body: {response.request.body}")
#        print(f"Status code: {response.status_code}")
#        print(f"Headers: {response.headers}")
        # Send login request
        response = self.client.post("/login", {"username": "test", "password": "test", "login": ""})
        print(f"###### Send login request for test user...")
        print(f"Request url: {response.request.url}")
        print(f"Request body: {response.request.body}")
        print(f"Response Status: {response.status_code}")
        print(f"Headers: {response.headers}")

        # set "token" from response header
        #self.client.headers.update({'Authorization': response.headers.get('token')})

        # OR set "token" from response cookies
        #self.client.cookies.set('Authorization', response.cookies.get('token'))

        # OR set "token" from response body
        #self.client.headers.update({'Authorization': str(response.content.decode().find('token'))})

    #        self.login()
#        #self.client.post("/login", {"username": "user", "password": "pass"})
#
#    def get_token(self):
#        response = self.client.get("/login")
#        # Sample string from response:
#        # <input id="csrf_token" name="csrf_token" type="hidden" value="REDACTED">
#        self.csrftoken = re.search(' name="csrf_token" .* value="(.+?)"', response.text).group(1)
#        print(f"DEBUG: self.csrftoken = {self.csrftoken}")
#
#    def login(self):
#        response = self.client.post("/login",
#                                    {"username_login": "user", "pwd": "pass"},
#                                    headers={"X-CSRFToken": self.csrftoken})
#        print(f"DEBUG: login response.status_code = {response.status_code}")

    @task(100)
    def load_page(self):
        self.client.get("/")
        self.client.get("/login")
        self.client.get("/dashboard")
        self.client.get("/transactions")
        self.client.get("/settings")

    @task(1)
    def gen_errors(self):
        self.client.post("/info")
        self.client.get("/help")