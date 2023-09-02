const express=require("express");
const app=express();
const bodyParser = require('body-parser');
const mysql = require('mysql');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const { exit } = require("process");
const { v4: uuidv4 } = require('uuid');
const http = require("http");
const { url } = require("inspector");
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const multer = require('multer');
const nocache = require('nocache');
const path = require('path')
const socketIo = require('socket.io');
const crypto = require('crypto');
const secretKey = crypto.randomBytes(64).toString('hex');
console.log(secretKey);
const server = http.createServer(app);
const io = socketIo(server); 
dotenv.config();
app.use(express.static(path.join(__dirname, 'public')));
/* mysql connection */
const con = mysql.createConnection({
  host: process.env.DB_CONNECT_HOST,
  user:process.env.DB_CONNECT_USER,
  password:  process.env.DB_CONNECT_PASS,
  database:process.env.DB_CONNECT_DATABASE
});
con.connect(function(err) {
  if (err) throw err;
  console.log("Connected!");
});
// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'attachments'); // Upload files to the "attachments" folder
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname); // Set unique file name for each upload
  }
});
const upload = multer({ storage: storage });
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
	secret: 'secret',
	resave: true,
	saveUninitialized: true
}));
app.get('/socket.io/socket.io.js', (req, res) => {
  res.sendFile(__dirname + '/node_modules/socket.io/client-dist/socket.io.js');
});
app.use('/attachments', express.static(path.join(__dirname, 'attachments')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'static')));
app.use(express.static(path.join(__dirname, "js")));
app.use(session({
  secret: 'secretkey',
  resave: false,
  saveUninitialized: true
}));
// set modules
app.set("view engine", "ejs");
app.set('views', path.join(__dirname, 'views'));
app.use(passport.initialize());
app.use(passport.session());
app.use('/userdashboard', nocache());
app.use('/admindashboard', nocache());
app.use(express.urlencoded({extended:true}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'ejs');
app.use(express.static("attachments"));
// Handle socket connections
io.on('connection', (socket) => {
  console.log('A user connected');

  socket.on('join', (data) => {
    const ticketId = data.ticketId;
    socket.join(ticketId); // Join the room associated with the ticketId

    // Fetch messages for the specific ticketId from the database
    const fetchMessagesQuery = 'SELECT * FROM chats WHERE ticketId = ?';
    con.query(fetchMessagesQuery, [ticketId], (err, rows) => {
      if (err) {
        console.error('Error fetching messages:', err);
      } else {
        const messages = rows.map(row => ({
          message: row.message,
          role: row.sendBy,
          createdAt:new Date(row.createdAt).toLocaleString()// Include createdAt from the database
        })); // Extract messages from all rows
        console.log(messages);
        // Emit fetched messages to the client
        io.to(ticketId).emit('initMessages', { messages: messages });
        console.log(messages);
      }
    });
  });
  socket.on('message', (data) => {
    // Assuming 'ticketId' is passed along with the message
    const ticketId = data.ticketId;
    const newMessage = data.message;
    const role = data.role;
    const createdAt = new Date().toLocaleString();
    // Fetch the current message from the database based on the ticketId
    const insertChatMessageQuery = 'INSERT INTO chats ( message, ticketId,sendBy) VALUES (?, ?, ?)';
con.query(insertChatMessageQuery, [ newMessage, ticketId,role], (err, result) => {
  if (err) {
    console.error('Error inserting chat message:', err);
  } else {
    console.log('Chat message inserted into the database');
  }
});
    // Broadcast the message to other clients in the room
    socket.broadcast.emit('message', { message: data.message, isSent: false });
    // Emit the sent message only to the sender
    socket.emit('message', { message: data.message, isSent: true ,role:data.role,createdAt: createdAt});
  });

  socket.on('disconnect', () => {
    console.log('A user disconnected');
  });
});
passport.use('local-user', new LocalStrategy(
  function(username, password, done) {
    // Fetch user from the database based on the username
    const sql = 'SELECT * FROM users WHERE username = ?';
    con.query(sql, [username], (err, rows) => {
      if (err) {
        return done(err);
      }
      if (!rows.length) {
        return done(null, false, { message: 'Incorrect username.' });
      }
      const user = rows[0];
      // Compare hashed password from the database with the provided password
      bcrypt.compare(password, user.password, function(err, result) {
        if (err || !result) {
          return done(null, false, { message: 'Incorrect password.' });
        }
        // Return the user object with role information (either 'user' or 'admin')
        return done(null, { id: user.id, role: user.role });
      });
    });
  }
));
// Serialize and deserialize user for session management
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  // Fetch user from the database based on the id
  const sql = 'SELECT * FROM users WHERE id = ?';
  con.query(sql, [id], (err, rows) => {
    if (err) {
      return done(err);
    }
    if (rows.length === 0) {
      // If the user was not found, return an error
      return done(new Error('User not found.'));
    }
    // Check the role of the user to differentiate between user and admin
    const user = rows[0];
    if (user.role === 'user') {
      // Regular user found
      done(null, { id: user.id, role: 'user',username: user.username  });
    } else if (user.role === 'admin') {
      // Admin found
      done(null, { id: user.id, role: 'admin',username: user.username  });
    }else if (user.role === 'localuser') {
      // Admin found
      done(null, { id: user.id, role: 'localuser',username: user.username  });
    } else {
      // Unknown role, return an error
      done(new Error('Unknown user role.'));
    }
  });
});
// Middleware to check if user is authenticated before accessing protected routes
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated() && (req.user.role === 'user' || req.user.role === 'admin'|| req.user.role === 'localuser')) {
    return next();
  }
  res.redirect('/login');
}
function checkRole(role) {
  return function(req, res, next) {
    // Check if the user is authenticated and has the correct role
    if (req.isAuthenticated() && req.user.role === role) {
      return next();
    }else if (req.isAuthenticated() && req.user.role === 'localuser') {
      // Redirect to the admin dashboard if the user is authenticated as an admin
      return res.redirect('/localuserdashboard');
    } else if (req.isAuthenticated() && req.user.role === 'admin') {
      // Redirect to the admin dashboard if the user is authenticated as an admin
      return res.redirect('/admindashboard');
    }else if (req.isAuthenticated() && req.user.role === 'user') {
      // Redirect to the admin dashboard if the user is authenticated as an admin
      return res.redirect('/userdashboard');
    } else {
      // User is not authenticated or doesn't have the correct role, redirect to login page
      return res.redirect('/login');
    }
  };
}
app.get('/login', (req, res) => {
  res.render('landing');
});
// Catch-all route for preventing direct URL access
app.use((req, res, next) => {
  const publicRoutes = ['/login','/reset-page']; // Add other public routes here if needed
  if (req.isAuthenticated() || publicRoutes.includes(req.path)) {
    // If the user is authenticated or the route is a public route, continue to the next middleware or route handler
    return next();
  }
  // If the user is not authenticated and the route is not a public route, redirect to the login page
  res.redirect('/login');
});
// // Login route to handle user and admin logins
app.post('/login', (req, res, next) => {
  const userType = req.body.userType;
 console.log(userType);
  // Use the appropriate passport strategy based on the userType (user or admin)
  if (userType === 'user') {
    passport.authenticate('local-user', {
      successRedirect: '/userdashboard',
      failureRedirect: '/login',
    })(req, res, next);
  } else if (userType === 'admin') {
    passport.authenticate('local-user', {
      successRedirect: '/admindashboard',
      failureRedirect: '/login',
    })(req, res, next);
  } else if (userType === 'localuser') {
    passport.authenticate('local-user', {
      successRedirect: '/localuserdashboard',
      failureRedirect: '/login',
    })(req, res, next);
  } else {
    // Invalid userType, redirect to login page
    res.redirect('/login');
  }
});
 app.get("/admincreateticket", function(req, res){
  const getUsersQuery = "SELECT username FROM users WHERE role IN ('admin', 'user')";
  con.query(getUsersQuery, (err, users) => {
    if (err) {
      console.error('Error fetching users:', err);
      return res.status(500).send('Error fetching users from the database.');
    }
    // Pass the users data to the 'index.ejs' template
    res.render("index", { users: users });
  });
});
 app.get("/usercreateticket", function(req, res){
  const getUsersQuery = "SELECT username FROM users";
  con.query(getUsersQuery, (err, users) => {
    if (err) {
      console.error('Error fetching users:', err);
      return res.status(500).send('Error fetching users from the database.');
    }
    // Pass the users data to the 'index.ejs' template
    res.render("userindex", { users: users });
  });
});
app.get("/localusercreateticket", function(req, res){
    // Pass the users data to the 'index.ejs' template
    res.render("localuserindex");
  });
app.get('/chat/:ticketId', (req, res) => {
    const ticketId = req.params.ticketId;
    const role= req.user.role;
    const getMessagesQuery = 'SELECT * FROM chats WHERE ticketId = ?';
    con.query(getMessagesQuery, [ticketId], (err, rows) => {
      if (err) {
        console.error('Error fetching messages:', err);
        return res.status(500).send('Error fetching messages from the database.');
      }
      // Return the messages as JSON response
      const messages = rows.map(row => ({
        message: row.message,
        role: row.sendBy, // Assuming you have a 'role' column in your 'chats' table
        createdAt: new Date(row.createdAt).toLocaleString() // Assuming you have a 'createdAt' column in your 'chats' table
      }));
    // Render the chat page with the specific ticketId and messages
    res.render('chat', { ticketId, role, messages});
  });
  });
// Set up the Socket.IO connection for a specific ticket ID
io.of('/chat/:ticketId').on('connection', (socket) => {
  const ticketId = socket.handshake.query.ticketId;
  console.log(`User connected to ticket ID: ${ticketId}`);
  
  // Define your socket event handlers for this specific ticket ID
  socket.on('message', (message) => {
    // Handle incoming messages for this ticket ID
    console.log(`Received message for ticket ID ${ticketId}: ${message}`);
    // Broadcast the message to other clients in this room, if needed
    socket.broadcast.emit('message', { message, isSent: false });
  });
  // More socket event handlers...
  // Handle disconnection
  socket.on('disconnect', () => {
    console.log(`User disconnected from ticket ID: ${ticketId}`);
    // Perform any necessary cleanup or updates related to this ticket ID
  });
});  
  app.use(express.static(__dirname + '/public'));
// Convert Date to MySQL date format (YYYY-MM-DD HH:mm:ss)
function convertToMySQLDateTime(dateString) {
  const date = new Date(dateString);
  return date.toISOString().slice(0, 19).replace('T', ' ');
}
app.post("/submit",upload.single('attachment'), function(req,res){
  const userId = req.user.id;
  // Fetch the user's username from the "users" table based on the user ID
  const userQuery = "SELECT username FROM users WHERE id = ?";
  con.query(userQuery, [userId], (userErr, userResult) => {
    if (userErr) {
      console.error('Error fetching user details:', userErr);
      return res.status(500).send('Error fetching user details.');
    }
    if (userResult.length === 0) {
      return res.status(404).send('User not found.');
    }
  const username = userResult[0].username;
  const { Description, Category, Progress, StartDate, DueDate, AssignedTo, Notes} = req.body;
 // Get the current date and time for "Created On" and "Modified On"
 const CreatedOn = convertToMySQLDateTime(new Date());
 const ModifiedOn = CreatedOn;
 const Attachment = req.file ? req.file.filename : null; // Get the uploaded file name or set it to null if no file was uploaded
 //console.log(Attachment);
 const CreatedBy = username;
 const ModifiedBy= username;
 const currentUserId = req.user.id; 
  const query="INSERT INTO tickets( Description, Category, Progress, StartDate, DueDate, AssignedTo, Notes, CreatedBy, CreatedOn, ModifiedBy, ModifiedOn ,Attachment,CreatorId) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
  console.log(StartDate);
  con.query(query, [ Description, Category, Progress, StartDate, DueDate, AssignedTo, Notes, CreatedBy, CreatedOn, ModifiedBy, ModifiedOn,Attachment,currentUserId], (err, result) => {
    if (err) {
      console.error('Error inserting data:', err);
      return res.status(500).send('Error inserting data into the database.');
    }
    console.log('Data successfully inserted.');
    // res.send('Data successfully submitted to the database!');
    res.redirect('/admindashboard');
  });
 })
})
app.post("/userdashboard/submit",upload.single('attachment'), function(req,res){
  const userId = req.user.id;
  const currentUserId = req.user.id; 
  // Fetch the user's username from the "users" table based on the user ID
  const userQuery = "SELECT username FROM users WHERE id = ?";
  con.query(userQuery, [userId], (userErr, userResult) => {
    if (userErr) {
      console.error('Error fetching user details:', userErr);
      return res.status(500).send('Error fetching user details.');
    }
    if (userResult.length === 0) {
      return res.status(404).send('User not found.');
    }
  const username = userResult[0].username;
  const { Description, Category, Progress, StartDate, DueDate, Notes} = req.body;  
 // Get the current date and time for "Created On" and "Modified On"
  const CreatedOn = convertToMySQLDateTime(new Date());
  const ModifiedOn = CreatedOn;
  const Attachment = req.file ? req.file.filename : null; // Get the uploaded file name or set it to null if no file was uploaded
  const ModifiedBy=username;
  const CreatedBy=username;
  const AssignedTo=username;
  const query="INSERT INTO tickets( Description, Category, Progress, StartDate, DueDate, AssignedTo, Notes, CreatedBy, CreatedOn, ModifiedBy, ModifiedOn ,Attachment,CreatorId) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
  con.query(query, [ Description, Category, Progress, StartDate, DueDate, AssignedTo, Notes, CreatedBy, CreatedOn, ModifiedBy, ModifiedOn,Attachment,currentUserId], (err, result) => {
    if (err) {
      console.error('Error inserting data:', err);
      return res.status(500).send('Error inserting data into the database.');
    }
  console.log('Data successfully inserted.');
    // res.send('Data successfully submitted to the database!');
  res.redirect('/userdashboard');
  });
})
})
app.post("/localuserdashboard/submit",upload.single('attachment'), function(req,res){
  const userId = req.user.id;
  const currentUserId = req.user.id; 
  // Fetch the user's username from the "users" table based on the user ID
  const userQuery = "SELECT username FROM users WHERE id = ?";
  con.query(userQuery, [userId], (userErr, userResult) => {
    if (userErr) {
      console.error('Error fetching user details:', userErr);
      return res.status(500).send('Error fetching user details.');
    }
    if (userResult.length === 0) {
      return res.status(404).send('User not found.');
    }
    const username = userResult[0].username;
  const { Description, Category, Progress, DueDate, AssignedTo, Notes} = req.body;
 // Get the current date and time for "Created On" and "Modified On"
 const CreatedOn = convertToMySQLDateTime(new Date());
 const ModifiedOn = CreatedOn;
 const Attachment = req.file ? req.file.filename : null; // Get the uploaded file name or set it to null if no file was uploaded
 const ModifiedBy=username;
 const CreatedBy=username;
  const query="INSERT INTO tickets( Description, Category, Progress, DueDate, AssignedTo, Notes, CreatedBy, CreatedOn, ModifiedBy, ModifiedOn ,Attachment,CreatorId) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
  con.query(query, [Description, Category, Progress, DueDate, AssignedTo, Notes, CreatedBy, CreatedOn, ModifiedBy, ModifiedOn,Attachment,currentUserId], (err, result) => {
    if (err) {
      console.error('Error inserting data:', err);
      return res.status(500).send('Error inserting data into the database.');
    }

    console.log('Data successfully inserted.');
    // res.send('Data successfully submitted to the database!');
    res.redirect('/localuserdashboard');
  });
})
})
app.get('/register', (req, res) => {
  res.render('register');
});
// Route to handle user registration form submission
app.post('/register', (req, res) => {
  const { username, password, role } = req.body;
  // Check if the username already exists in the database
  const checkUsernameQuery = 'SELECT * FROM users WHERE username = ?';
  con.query(checkUsernameQuery, [username], (err, rows) => {
    if (err) {
      console.error('Error checking username:', err);
      return res.status(500).send('Error checking username in the database.');
    }
    if (rows.length > 0) {
      // Username already exists, redirect back to the registration form with an error message
      return res.render('register', { error: 'Username already exists. Please choose a different username.' });
    }
    // If the username does not exist, hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error('Error hashing password:', err);
        return res.status(500).send('Error hashing password.');
      }
      // Insert the new user data into the database
      const insertUserQuery ='INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
      con.query(insertUserQuery, [username, hashedPassword, role], (err, result) => {
        if (err) {
          console.error('Error inserting user data:', err);
          return res.status(500).send('Error inserting user data into the database.');
        }
        console.log('New user successfully registered.');
        res.redirect('/admindashboard'); // Redirect to the admin dashboard after successful registration
      });
    });
  });
});
app.get('/reset-page',(req,res)=>{
 res.render('update');
})
app.post('/reset-page', (req, res) => {
  const { username, newPassword } = req.body;

  // Check if the username exists in the database
  const checkUsernameQuery = 'SELECT * FROM users WHERE username = ?';
  con.query(checkUsernameQuery, [username], (err, rows) => {
    if (err) {
      console.error('Error checking username:', err);
      return res.status(500).send('Database error');
    }

    if (rows.length === 0) {
      return res.send('Username not found.');
    }

    // Hash the new password
    bcrypt.hash(newPassword, 10, (hashErr, hashedPassword) => {
      if (hashErr) {
        console.error('Error hashing password:', hashErr);
        return res.status(500).send('Password hashing error');
      }

      // Update the password for the user
      const updatePasswordQuery = 'UPDATE users SET password = ? WHERE username = ?';
      con.query(updatePasswordQuery, [hashedPassword, username], (updateErr) => {
        if (updateErr) {
          console.error('Error updating password:', updateErr);
          return res.status(500).send('Password update error');
        }
        res.redirect('landing');
      });
    });
  });
});
//Route to display the user dashboard
app.get('/userdashboard', isAuthenticated, checkRole('user'), nocache(), (req, res) => {
  const filterOption = req.query.filterOption;
  const progress = req.query.Progress; // Access the "Progress" value from the form
  const username = req.user.username; // Get the username of the logged-in user

  // Construct the SQL query to fetch tickets assigned to the logged-in user
  let sql = 'SELECT * FROM tickets WHERE AssignedTo = ?';

  // Add a condition to filter by "Progress" if a value is selected in the dropdown
  if (progress) {
    sql += ' AND Progress = ?';
  }

  con.query(sql, [username, progress], (err, rows) => {
    if (err) {
      console.error('Error fetching data:', err);
      return res.status(500).send('Error fetching data from the database.');
    }
    res.render('userdashboard', { tickets: rows, filterOption: progress ,username});
  });
});
// Route to display the admin dashboard
app.get('/admindashboard', isAuthenticated, checkRole('admin'),nocache(),(req, res) => {
  const userId = req.query.Id;
  const username= req.user.username;
  const filterOption = req.query.filterOption;
  const progress = req.query.Progress; // Access the "Progress" value from the form
  // If a user ID is provided, fetch the user based on the ID from the database
  if (userId) {
    const sql = 'SELECT * FROM tickets WHERE Id = ?';
    con.query(sql, [userId], (err, rows) => {
      if (err) {
        console.error('Error fetching data:', err);
        return res.status(500).send('Error fetching data from the database.');
      }
      res.render('admindashboard', { tickets: rows,username });
    });
  } else {
    // If no user ID is provided, fetch all tickets from the database with filter
    let sql = 'SELECT * FROM tickets';
    // Add a condition to filter by "Progress" if a value is selected in the dropdown
    if (progress) {
      sql += ' WHERE Progress = ?';
    }
    con.query(sql, [progress], (err, rows) => {
      if (err) {
        console.error('Error fetching data:', err);
        return res.status(500).send('Error fetching data from the database.');
      }
      res.render('admindashboard', { tickets: rows, filterOption: progress,username });
    });
  }
});
app.get('/localuserdashboard', isAuthenticated, checkRole('localuser'), nocache(), (req, res) => {
  const userId = req.query.Id;
  const filterOption = req.query.filterOption;
  const username= req.user.username;
  const progress = req.query.Progress; // Access the "Progress" value from the form
  const currentUserId = req.user.id;
  // If a user ID is provided, fetch the user based on the ID from the database
  if (userId) {
    const sql = 'SELECT * FROM tickets WHERE Id = ? AND CreatorId = ?';
    con.query(sql, [userId, currentUserId], (err, rows) => {
      if (err) {
        console.error('Error fetching data:', err);
        return res.status(500).send('Error fetching data from the database.');
      }
      res.render('localuserdashboard', { tickets: rows,username });
    });
  } else {
    // If no user ID is provided, fetch tickets created by the same user with filter
    let sql = 'SELECT * FROM tickets WHERE CreatorId = ?';

    // Add a condition to filter by "Progress" if a value is selected in the dropdown
    if (progress) {
      sql += ' AND Progress = ?';
    }
    con.query(sql, [currentUserId, progress], (err, rows) => {
      if (err) {
        console.error('Error fetching data:', err);
        return res.status(500).send('Error fetching data from the database.');
      }
      res.render('localuserdashboard', { tickets: rows, filterOption: progress,username });
    });
  }
});
app.get('/edit/:id', (req, res) => {
  const ticketId = req.params.id;
  // Fetch the ticket data from the database for the specific ticketId
  const sql = 'SELECT * FROM tickets WHERE Id = ?';
  con.query(sql, [ticketId], (err, rows) => {
    if (err) {
      console.error('Error fetching ticket data:', err);
      return res.status(500).send('Error fetching ticket data from the database.');
    }
    // Fetch the names from the users table
    const userQuery = "SELECT username FROM users WHERE role IN ('admin', 'user')";
    con.query(userQuery, (userErr, users) => {
      if (userErr) {
        console.error('Error fetching user names:', userErr);
        return res.status(500).send('Error fetching user names from the database.');
      }
      console.log('Users fetched successfully:', users);
      // Render the 'edit.ejs' template with the ticket data and user names
      res.render('edit', { ticket: rows[0], users: users });
    });
  });
});
app.get('/useredit/:id', (req, res) => {
  const ticketId = req.params.id;
  // Fetch the ticket data from the database for the specific ticketId
  const sql = 'SELECT * FROM tickets WHERE Id = ?';
  con.query(sql, [ticketId], (err, rows) => {
    if (err) {
      console.error('Error fetching ticket data:', err);
      return res.status(500).send('Error fetching ticket data from the database.');
    }
    // Render the 'edit.ejs' template with the ticket data
    res.render('useredit', { ticket: rows[0] }); // We expect only one row since Id is unique
  });
});
app.post('/update/:id', upload.single('attachment'), (req, res) => {
  const ticketId = req.params.id;
  const userId = req.user.id;
  // Fetch the user's username from the "users" table based on the user ID
  const userQuery = "SELECT username FROM users WHERE id = ?";
  con.query(userQuery, [userId], (userErr, userResult) => {
    if (userErr) {
      console.error('Error fetching user details:', userErr);
      return res.status(500).send('Error fetching user details.');
    }
    if (userResult.length === 0) {
      return res.status(404).send('User not found.');
    }
    const username = userResult[0].username;
    const { Description, Category,StartDate, AssignedTo, Notes, DueDate } = req.body;
    // Get the current date and time for "Modified On"
    const ModifiedOn = convertToMySQLDateTime(new Date());
    const attachment = req.file ? req.file.filename : (req.body.attachment || '');
    // Construct the SQL update statement based on the provided data in the form
    let sql = 'UPDATE tickets SET ModifiedBy = ?, ModifiedOn = ?';
    const values = [username, ModifiedOn];
    if (Description) {
      sql += ', Description = ?';
      values.push(Description);
    }
    if (Category) {
      sql += ', Category = ?';
      values.push(Category);
    }
    if (AssignedTo) {
      sql += ', AssignedTo = ?';
      values.push(AssignedTo);
    }
    if (Notes) {
      sql += ', Notes = ?';
      values.push(Notes);
    }
    if (DueDate) {
      sql += ', DueDate = ?';
      values.push(DueDate);
    }
    if (StartDate) {
      sql += ', StartDate = ?';
      values.push(StartDate);
    }
    if (attachment) {
      sql += ', attachment = ?';
      values.push(attachment);
    }
    sql += ' WHERE Id = ?';
    values.push(ticketId);
    // Update the ticket data in the database
    con.query(sql, values, (err, result) => {
      if (err) {
        console.error('Error updating data:', err);
        return res.status(500).send('Error updating data in the database.');
      }
      console.log('Data successfully updated.');
      res.redirect('/admindashboard'); // Redirect to the dashboard after successful update
    });
  });
});
app.post('/userdashboard/update/:id', upload.single('attachment'),(req, res) => {
  const ticketId = req.params.id;
  const userId = req.user.id;
  // Fetch the existing attachment from the database
  const getAttachmentQuery = "SELECT attachment FROM tickets WHERE Id = ?";
  con.query(getAttachmentQuery, [ticketId], (getAttachmentErr, getAttachmentResult) => {
    if (getAttachmentErr) {
      console.error('Error fetching existing attachment:', getAttachmentErr);
      return res.status(500).send('Error fetching existing attachment from the database.');
    }
  // Fetch the user's username from the "users" table based on the user ID
  const userQuery = "SELECT username FROM users WHERE id = ?";
  con.query(userQuery, [userId], (userErr, userResult) => {
    if (userErr) {
      console.error('Error fetching user details:', userErr);
      return res.status(500).send('Error fetching user details.');
    }
    if (userResult.length === 0) {
      return res.status(404).send('User not found.');
    }
  const username = userResult[0].username;
  const {  Progress, AssignedTo, Notes} = req.body;
  //Get the current date and time for "Modified On"
  const ModifiedOn = convertToMySQLDateTime(new Date());
  const attachment = req.file ? req.file.filename : (req.body.attachment || getAttachmentResult[0].attachment || '');
  const ModifiedBy=username;
  // Update the ticket data in the database
  const sql = 'UPDATE tickets SET  Progress = ? , Notes = ?, ModifiedBy = ?, ModifiedOn = ? , attachment=? WHERE Id = ?';
  con.query(sql, [ Progress, Notes, ModifiedBy, ModifiedOn, attachment, ticketId], (err, result) => {
    if (err) {
      console.error('Error updating data:', err);
      return res.status(500).send('Error updating data in the database.');
    }
    console.log('Data successfully updated.');
    res.redirect('/userdashboard'); // Redirect to the dashboard after successful update
  });
});
});
});
// Route to handle logout
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/login'); // Redirect to the login page after logout
  });
});
const serverPort = 4000;
server.listen(serverPort, () => {
  console.log(`Server listening on port ${serverPort}`);
});
module.exports =app ;
