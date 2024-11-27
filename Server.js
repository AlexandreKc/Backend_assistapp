// Modulos necesarios
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');

// Instancia express
const app = express();
const port = process.env.PORT || 3000;

// Para realizar consultas sin importar el port
app.use(cors());
app.use(express.json());

// Conexión a MySQL
const connection = mysql.createConnection({
  host: process.env.DB_SERVER,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});


// Establecer la conexión con MySQL
connection.connect((err) => {
  if (err) {
    console.error('Error conectando a MySQL:', err.stack);
    return;
  }
  console.log('Conectado a MySQL con ID de conexión:', connection.threadId);
});

// Ruta para manejar el login
app.post('/login', (req, res) => {
  const { correo, password } = req.body;
  
  // Verificar que se proporcionaron el correo y la contraseña
  if (!correo || !password) {
    return res.status(400).json({ message: 'Por favor, proporciona correo y contraseña' });
  }
  
  // Consulta para verificar las credenciales y obtener el nombre y el tipo de usuario
  connection.query('SELECT nombre, id_tp_usuario FROM usuario WHERE correo = ? AND contrasena = ?', [correo, password], (err, results) => {
    if (err) {
      console.error('Error en la consulta:', err.stack);
      return res.status(500).send('Error en la consulta');
    }
    
    if (results.length > 0) {
      // Si el usuario existe, devolver el nombre y el id_tp_usuario
      res.json({
        valid: true,
        nombre: results[0].nombre,
        id_tp_usuario: results[0].id_tp_usuario // Incluir el tipo de usuario en la respuesta
      });
    } else {
      // Si no se encuentra el usuario, devolver respuesta inválida
      res.json({ valid: false });
    }
  });
});

// Endpoint para registrar un nuevo usuario
app.post('/registro', (req, res) => {
  const { nombre, correo, contrasena } = req.body;
  
  // Validaciones de entrada
  if (!nombre || !correo || !contrasena) {
    return res.status(400).json({ error: 'Todos los campos son requeridos.' });
  }
  
  // Añadir la lógica para guardar el nuevo usuario en la base de datos
  const query = 'INSERT INTO usuario (correo, nombre, contrasena, id_tp_usuario) VALUES (?, ?, ?, 1)'; // id_tp_usuario por defecto es 1
  connection.query(query, [correo, nombre, contrasena], (error, results) => {
    if (error) {
      return res.status(500).json({ error: 'Correo ya registrado, recupera tu contraseña' });
    }
    res.status(201).json({ message: 'Usuario fue registrado con éxito.' });
  });
});


// Ruta para verificar si el correo existe
app.post('/validar-correo', (req, res) => {
  const { correo } = req.body; // Obtener el correo del cuerpo de la solicitud
  
  // Consulta a la base de datos
  const query = 'SELECT * FROM usuario WHERE correo = ?';
  connection.query(query, [correo], (err, results) => {
    if (err) {
      res.status(500).json({ error: 'Error en el servidor' });
    } else {
      if (results.length > 0) {
        res.json({ existe: true });
      } else {
        res.json({ existe: false });
      }
    }
  });
});

// Ruta para cambiar la contraseña
app.post('/cambiar-contrasena', (req, res) => {
  const { correo, nuevaContrasena } = req.body;

  // Verificar que se proporcionaron el correo y la nueva contraseña
  if (!correo || !nuevaContrasena) {
    return res.status(400).json({ message: 'Por favor, proporciona el correo y la nueva contraseña' });
  }

  // Consulta para actualizar la contraseña
  const query = 'UPDATE usuario SET contrasena = ? WHERE correo = ?';
  connection.query(query, [nuevaContrasena, correo], (err, results) => {
    if (err) {
      console.error('Error en la consulta:', err.stack);
      return res.status(500).json({ message: 'Error al cambiar la contraseña' });
    }

    if (results.affectedRows > 0) {
      // Si se actualizó la contraseña
      res.json({ message: 'Contraseña cambiada exitosamente' });
    } else {
      // Si no se encontró el usuario
      res.status(404).json({ message: 'Correo no registrado' });
    }
  });
});

// Ruta para obtener todos los usuarios (ejemplo)
app.get('/usuarios', (req, res) => {
  connection.query('SELECT * FROM usuario', (err, results) => {
    if (err) {
      console.error('Error en la consulta:', err.stack);
      return res.status(500).send('Error en la consulta');
    }
    res.json(results);
  });
});

app.post('/cambiar-contrasena', (req, res) => {
  const { correo, nuevaContrasena } = req.body;
  
  // Validar que el correo y la nueva contraseña no sean nulos
  if (!correo || !nuevaContrasena) {
    return res.status(400).send({ error: 'Correo y contraseña son obligatorios.' });
  }
  
  // Cambiar contrasena
  Usuario.findOneAndUpdate({ correo: correo }, { contrasena: nuevaContrasena }, { new: true })
  .then(usuario => {
    if (!usuario) {
      return res.status(404).send({ error: 'Usuario no encontrado.' });
    }
    res.send({ success: 'Contraseña cambiada exitosamente.' });
  })
  .catch(err => {
    console.error('Error al cambiar la contraseña:', err);
    res.status(500).send({ error: 'Error en el servidor.' });
  });
});


// Iniciar el servidor
app.listen(PORT, () => {
  console.log(`Servidor en funcionamiento en http://localhost:${PORT}`);
});
