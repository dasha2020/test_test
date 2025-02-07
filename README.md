# test_test

This is the example of forum that can be implemented in your website. It's built with FastAPI, SQLAlchemy. 
There is one **SUPER ADMIN** and others are **CUSTOMERS**. **CUSTOMERS** can ask for admin access and be granted the admin role. 
### What you can do with it:
1. Register as a customer
2. Customers can ask questions 
3. Customers can get the info about their question, which includes: status (read, unread, answered); answer (if admin or super_admin answered); the question itself 
4. Customers can ask for admin access 
5. Super_admin or admins can look through questions and answer them and change the its status 
6. Super_admin can grant customers **ADMIN** access and also change their role back to the **CUSTOMER** 

### Project Structure: 
1. README.md
2. main.py
3. database.py
4. models.py
5. userbase.db

### To start the application use this line in your terminal: 
```
uvicorn main:app --reload
```

This will start your server and with `/docs` and FastAPI Swagger UI you can test this application. 

Make sure all libraries and packages are installed. 