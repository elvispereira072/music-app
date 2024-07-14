const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Conectar ao MongoDB
mongoose.connect('mongodb://localhost:27017/ecommerce', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB conectado')).catch(err => console.log(err));

// Definir modelo de Usuário
const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    date: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// Configuração do nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'seuemail@gmail.com',
        pass: 'suasenha'
    }
});

// Rotas de Autenticação
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) return res.status(400).send('Usuário já existe');
        
        const hashedPassword = await bcrypt.hash(password, 10);
        user = new User({ name, email, password: hashedPassword });
        await user.save();

        const token = jwt.sign({ id: user._id }, 'secret', { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).send('Erro no servidor');
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).send('Credenciais inválidas');
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Credenciais inválidas');
        
        const token = jwt.sign({ id: user._id }, 'secret', { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).send('Erro no servidor');
    }
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).send('Usuário não encontrado');

        const resetToken = jwt.sign({ id: user._id }, 'resetSecret', { expiresIn: '1h' });

        const mailOptions = {
            from: 'seuemail@gmail.com',
            to: email,
            subject: 'Recuperação de Senha',
            text: `Clique no link para resetar sua senha: http://localhost:5000/reset-password?token=${resetToken}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) return res.status(500).send('Erro ao enviar email');
            res.send('Email enviado para resetar senha');
        });
    } catch (err) {
        res.status(500).send('Erro no servidor');
    }
});

// Servir arquivos estáticos
app.use(express.static(path.join(__dirname, '../frontend')));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
