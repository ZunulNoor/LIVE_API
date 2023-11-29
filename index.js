const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const mysql = require('mysql2');
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
require('dotenv').config()
const port = process.env.PORT || 3000
const salt = 10
const app = express()
// <============================================ M I D D L E  W A R E ===================================================> 


app.use(express.json());
app.use(cors({
  origin: "*",
  methods: "*",
}));
app.use(cookieParser())

// <========================================= C O N N E C T I O N ==========================================================>

const db = mysql.createConnection({
  port: process.env.MYSQL_ADDON_PORT,
  host: process.env.MYSQL_ADDON_HOST,
  user: process.env.MYSQL_ADDON_USER,
  password: process.env.MYSQL_ADDON_PASSWORD,
  database: process.env.MYSQL_ADDON_DB,
  queueLimit: 0
});

db.connect((err) => {
  if (err) {
    throw err;
  }
  console.log('Connected to MySQL');
});


// <========================================== R E G I  S T R A T I O N ============================================>
app.post('/signup', (req, res) => {
  const sql = "INSERT INTO users(`name`, `email`, `password`, `role`) VALUES (?)";
  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if (err) return res.json({ Error: "Error for hashing password" })
    const values = [
      req.body.name,
      req.body.email,
      hash,
      req.body.role
    ]
    db.query(sql, [values], (err, result) => {
      if (err) return res.json({ Error: "Inserting data Error" });
      return res.json({ Status: "Success" })
    })
  })
});

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ Error: "You are not authenticated" });
  } else {
    jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
      if (err) {
        return res.json({ Error: "Token is not correct" });
      } else {
        req.name = decoded.name;
        // req.role = decoded.role;
        next();
      }
    });
  }
};

app.get('/', verifyUser, (req, res) => {
  return res.json({ Status: "Success", name: req.name });
});

app.post('/login', (req, res) => {
  const sql = "SELECT * from users WHERE email = ?"
  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.json({ Error: "Login Error" })
    if (data.length > 0) {
      bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
        if (err) return res.json({ Error: "Password Compared Error" })
        if (response) {
          const name = data[0].name
          const token = jwt.sign({ name }, process.env.SECRET_KEY, { expiresIn: '1d' })
          res.cookie('token', token)
          return res.json({ Status: "Success" })
        } else {
          return res.json({ Error: "Password not matched" })
        }
      })
    } else {
      return res.json({ Error: "No email exists" })
    }
  })
})

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  return res.json({ Status: "Success" })
})
// ======================================================================================================

// app.get('*',(req,res)=>{
//   res.sendFile(path.join(__dirname,'./client/dist/index.html'))
// })


app.listen(port, () => {
  console.log(`Example App Listening on ${port}`)
})