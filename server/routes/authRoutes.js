import express from 'express'
import {connectToDatabase} from '../lib/db.js'
import bcyrpt from 'bcrypt';
import jwt from 'jsonwebtoken'

const router = express.Router()

router.post('/register', async (req, res) => {
    const {username, email, password} = req.body;
    try {
        const db = await connectToDatabase()
        const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email])
        if(rows.length > 0) {
            return res.status(409).json({message : "user already existed"})
        }
        const hashPassword = await bcyrpt.hash(password, 10)
        await db.query("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
            [username, email, hashPassword])
        
        return res.status(201).json({message: "user created successfully"})
    } catch(err) {
        console.error('Error occurred:', err);
        return res.status(500).json(err.message)
    }
})


router.post('/login', async (req, res) => {
    const {email, password} = req.body;
    try {
        const db = await connectToDatabase()
        const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email])
        if(rows.length === 0) {
            return res.status(404).json({message : "user not existed"})
        }
       const isMatch = await bcyrpt.compare(password, rows[0].password)
        if (!isMatch) {
            return res.status(404).json({message : "wrong password"})
        }
        const token = jwt.sign({id: rows[0].id}, process.env.JWT_KEY, {expiresIn: '3h'})
        return res.status(201).json({token: token})
    } catch(err) {
        console.error('Error occurred:', err);
        return res.status(500).json(err.message)
    }
})


export default router;