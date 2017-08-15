const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const config = require('config')
const mysql = require('mysql')
const bcrypt = require('bcrypt')
const uuid = require('uuid')

app.use(bodyParser.urlencoded({extended:false}))
app.use(bodyParser.json())


const conn = mysql.createConnection({
host: config.get('db.host'),
database: config.get('db.database'),
user: config.get('db.user'),
password: config.get('db.password')
})


app.post('/token', function(req, res, next){
  const username = req.body.username
  const password = req.body.password

console.log(username, password)

const sql = `
  SELECT password FROM users
  WHERE username = ?
`
  conn.query(sql,[username], function(err, results, fields){
    console.log(results)
  const hashedPassword = results[0].password

  bcrypt.compare(password, hashedPassword).then(function(result){
      if(result){
        const token = uuid()
        const tokenUpdateSQL = `
          UPDATE users
          SET token = ?
          WHERE username = ?
          `
        conn.query(tokenUpdateSQL, [token, username], function(err, results, fields){
          res.json({
          token:token
           })
         })

        } else {
              res.status(401).json({
                message: 'Invalid username or password'
       })
      }
    })
  })
})
app.post('/register',function(req,res,next){
  const username = req.body.username
  const password = req.body.password
  const token = uuid()


  const sql =`
  INSERT INTO users(username, password)
  VALUES (?, ?)
  `
  bcrypt.hash(password, 10).then (function(hashedPassword){
    conn.query(sql,[username,hashedPassword, token], function(err, results, fields){
      res.json({
        message: "user registered"
      })
    })
  })
})


app.get("/", function(req, res, next){
  res.render("index", {appType:"Express"})
})

app.listen(3000, function(){
  console.log("App running on port 3000")
})
