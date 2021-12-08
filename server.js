const express = require('express')
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')

app.use(express.json())

const users = [
    {
    email: "bhavya@email.com",
    password: "password"
},
{
    email: "jha@email.com",
    password: "jha2"
}
];

app.get('/users', authenticateToken, (req,res) => {
    res.json(users.filter(user => user.email==req.body.email));
})

app.post('/users', async (req, res) => {
    try{
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        console.log(salt);
        console.log(hashedPassword);
        const user = {email: req.body.email, password: hashedPassword};
        users.push(user)
        res.status(201).send();
    } catch {
        res.status(500).send();
    }
})

app.post('/users/login', async (req, res) => {
    const user = users.find(user => user.email = req.body.email)
    if(!user) {
        return res.status(400).send('Cannot find User');
    }
    try {
       if( await bcrypt.compare(req.body.password, user.password)){
            const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
            res.json({ accessToken: accessToken})
           res.send('Login Successful!')
       } else {
           res.send('Invalid Password')
       }
    } catch {
        res.status(500).send();
    }
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1] //cause the format will be as- Bearer token
    if(token==null) {
        return res.status(401).send('Token undefined');
    }
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if(err) {
            return res.status(403).send('Session Expired');
        }
        req.user = user;
        next();
    })
}

app.listen(5000, () => {
    console.log('listening on port 5000');
});