const cors = require('cors')
const express = require('express')
const mysql = require('mysql2/promise')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const session = require('express-session')
const bcrypt = require('bcrypt')

const app = express()
app.use(express.json())
app.use(cors({
  credentials: true,
  origin: ['http://localhost:8888']
}))
app.use(cookieParser())

app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: true
}))

const port = 8000
const secret = 'mysecret'

let conn = null

// function init connection mysql
const initMySQL = async () => {
  conn = await mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'tutorial'
  })
}

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body
  
  const [rows] = await conn.query('SELECT * FROM users WHERE email = ?', email)
  if (rows.length) {
      return res.status(400).send({ message: 'Email is already registered' })
  }

  // Hash the password
  const hash = await bcrypt.hash(password, 10)

  // Store the user data
  const userData = { email, password: hash }

  try {
    const result = await conn.query('INSERT INTO users SET ?', userData)
  } catch (error) {
    console.error(error)
    res.status(400).json({
      message: 'insert fail',
      error
    })
  }

  res.status(201).send({ message: 'User registered successfully' })
})

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body

  const [result] = await conn.query('SELECT * from users WHERE email = ?', email)
  const user = result[0]
  const match = await bcrypt.compare(password, user.password)
  if (!match) {
    return res.status(400).send({ message: 'Invalid email or password' })
  }
  // Create a token
  const token = jwt.sign({ email, role: 'test' }, secret, { expiresIn: '1h' })

  res.cookie('token', token, {
    maxAge: 300000,
    secure: true,
    httpOnly: true,
    sameSite: "none",
  })

  req.session.userId = user.id
  console.log('save session', req.session.userId)

  res.send({ message: 'Login successful', token })
})

const authenticateToken = (req, res, next) => {
  // const authHeader = req.headers['authorization']
  // const token = authHeader && authHeader.split(' ')[1]
  const token = req.cookies.token
  console.log('session', req.session.userId)

  if (token == null) return res.sendStatus(401) // if there isn't any token

  try {
    const user = jwt.verify(token, secret)
    req.user = user
    console.log('user', user)
    next()
  } catch (error) {
    return res.sendStatus(403)
  }
}

app.get('/api/users', authenticateToken, async (req, res) => {
    try {
      // Get the users
      const [results] = await conn.query('SELECT email FROM users')
      const users = results.map(row => row.email)

      res.send(users)
    } catch (err) {
      console.error(err)
      res.status(500).send({ message: 'Server error' })
    }
})

// Listen
app.listen(port, async () => {
  await initMySQL()
  console.log('Server started at port 8000')
})