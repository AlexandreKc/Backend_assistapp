// Modulos necesarios
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');

// Instancia express
const app = express();
const port = process.env.PORT || 3000;

// Para realizar consultas sin importar el port
app.use(cors());
app.use(express.json());

// Crear un pool de conexiones
const pool = mysql.createPool({
  host: process.env.DB_SERVER,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,  // Ajusta el límite de conexiones según lo necesites
  queueLimit: 0
});

// Usar el pool para realizar consultas
app.post('/login', (req, res) => {
  const { correo, password } = req.body;
  
  // Verificar que se proporcionaron el correo y la contraseña
  if (!correo || !password) {
    return res.status(400).json({ message: 'Por favor, proporciona correo y contraseña' });
  }
  
  // Usar el pool para consultar la base de datos
  pool.query('SELECT id, nombre, id_tp_usuario, contrasena FROM usuario WHERE correo = ?', [correo], (err, results) => {
    if (err) {
      console.error('Error en la consulta:', err.stack);
      return res.status(500).send('Error en la consulta');
    }

    if (results.length > 0) {
      // Si el usuario existe, verificar la contraseña encriptada
      bcrypt.compare(password, results[0].contrasena, (err, isMatch) => {
        if (err) {
          return res.status(500).json({ message: 'Error al verificar la contraseña' });
        }

        if (isMatch) {
          // Si las contraseñas coinciden
          res.json({
            valid: true,
            id: results[0].id,  // Enviar el ID del usuario
            nombre: results[0].nombre,
            id_tp_usuario: results[0].id_tp_usuario // Incluir el tipo de usuario en la respuesta
          });
        } else {
          // Si las contraseñas no coinciden
          res.json({ valid: false });
        }
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

  // Encriptar la contraseña antes de guardarla
  bcrypt.hash(contrasena, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ error: 'Error al encriptar la contraseña' });
    }

    // Añadir la lógica para guardar el nuevo usuario en la base de datos
    const query = 'INSERT INTO usuario (correo, nombre, contrasena, id_tp_usuario) VALUES (?, ?, ?, 1)'; // id_tp_usuario por defecto es 1
    pool.query(query, [correo, nombre, hashedPassword], (error, results) => {
      if (error) {
        return res.status(500).json({ error: 'Correo ya registrado, recupera tu contraseña' });
      }
      res.status(201).json({ message: 'Usuario fue registrado con éxito.' });
    });
  });
});

// Ruta para verificar si el correo existe
app.post('/validar-correo', (req, res) => {
  const { correo } = req.body; // Obtener el correo del cuerpo de la solicitud
  
  // Consulta a la base de datos
  const query = 'SELECT * FROM usuario WHERE correo = ?';
  pool.query(query, [correo], (err, results) => {
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

  if (!correo || !nuevaContrasena) {
    return res.status(400).json({ message: 'Por favor, proporciona el correo y la nueva contraseña' });
  }

  // Encriptar la nueva contraseña antes de actualizarla
  bcrypt.hash(nuevaContrasena, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ message: 'Error al encriptar la nueva contraseña' });
    }

    const query = 'UPDATE usuario SET contrasena = ? WHERE correo = ?';
    pool.query(query, [hashedPassword, correo], (err, results) => {
      if (err) {
        console.error('Error en la consulta:', err.stack);
        return res.status(500).json({ message: 'Error al cambiar la contraseña' });
      }

      if (results.affectedRows > 0) {
        res.json({ message: 'Contraseña cambiada exitosamente' });
      } else {
        res.status(404).json({ message: 'Correo no registrado' });
      }
    });
  });
});

// Ruta para obtener todos los usuarios (ejemplo)
app.get('/usuarios', (req, res) => {
  pool.query('SELECT * FROM usuario', (err, results) => {
    if (err) {
      console.error('Error en la consulta:', err.stack);
      return res.status(500).send('Error en la consulta');
    }
    res.json(results);
  });
});
// Endpoint para obtener las materias asociadas a un usuario
app.get('/materias/usuario/:usuarioId', (req, res) => {
  const { usuarioId } = req.params;  // Obtener el usuarioId de los parámetros de la URL

  if (!usuarioId) {
    return res.status(400).json({ message: 'Por favor, proporciona un usuarioId' });
  }

  // Consulta para obtener las materias asociadas al usuario
  const query = `
    SELECT um.materia_id, m.nombre, m.descripcion 
    FROM usuario_materia um 
    INNER JOIN materias m ON um.materia_id = m.id 
    WHERE um.usuario_id = ?;
  `;

  // Realizar la consulta usando el pool de conexiones
  pool.query(query, [usuarioId], (err, results) => {
    if (err) {
      console.error('Error al obtener las materias:', err.stack);
      return res.status(500).json({ message: 'Error al obtener las materias' });
    }

    // Enviar las materias como respuesta en formato JSON
    res.json(results);
  });
});
// Endpoint para obtener todas las materias
app.get('/materias', (req, res) => {
  pool.query('SELECT * FROM materias', (err, results) => {
    if (err) {
      console.error('Error en la consulta:', err.stack);
      return res.status(500).send('Error en la consulta');
    }
    res.json(results);
  });
});
// Ruta para crear una nueva clase
app.post('/crear-clase', (req, res) => {
  const { idMateria } = req.body;

  // Validar si se proporcionó el idMateria
  if (!idMateria) {
    return res.status(400).json({ message: 'Por favor, proporciona el id de la materia' });
  }

  // Obtener el nombre de la materia para generar el nombre de la clase
  pool.query('SELECT nombre FROM materias WHERE id = ?', [idMateria], (err, results) => {
    if (err) {
      console.error('Error al obtener los detalles de la materia:', err.stack);
      return res.status(500).json({ message: 'Error al obtener los detalles de la materia' });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'Materia no encontrada' });
    }

    const nombreMateria = results[0].nombre;

    // Obtener el número de la última clase creada para esta materia
    pool.query('SELECT COUNT(*) AS totalClases FROM clases WHERE id_materia = ?', [idMateria], (err, results) => {
      if (err) {
        console.error('Error al contar las clases:', err.stack);
        return res.status(500).json({ message: 'Error al contar las clases' });
      }

      const claseNumero = results[0].totalClases + 1;  // Incrementar el número de clase

      // Generar el nombre de la clase concatenando el nombre de la materia y el número de clase
      const nombreClase = `${nombreMateria} clase ${claseNumero}`;

      // Crear el ID de la nueva clase (6 caracteres aleatorios)
      const idClase = Math.random().toString(36).substring(2, 8).toUpperCase();

      // Obtener la fecha actual
      const fechaCreacion = new Date();

      // Insertar la nueva clase en la base de datos
      pool.query(
        'INSERT INTO clases (id_clase, id_materia, nombre, fecha_creacion) VALUES (?, ?, ?, ?)',
        [idClase, idMateria, nombreClase, fechaCreacion],
        (err, results) => {
          if (err) {
            console.error('Error al insertar la clase:', err.stack);
            return res.status(500).json({ message: 'Error al insertar la clase' });
          }

          res.status(201).json({
            message: 'Clase creada exitosamente',
            idClase: idClase,  
            nombreClase: nombreClase  
          });
        }
      );
    });
  });
});


// Ruta para obtener todas las clases de una materia específica
app.get('/clases/materia/:materiaId', (req, res) => {
  const { materiaId } = req.params;  // Obtener el materiaId de los parámetros de la URL

  if (!materiaId) {
    return res.status(400).json({ message: 'Por favor, proporciona un materiaId' });
  }

  // Consulta para obtener las clases asociadas a la materia
  const query = `
    SELECT c.id_materia, c.id_clase, c.nombre, c.fecha_creacion 
    FROM clases c
    WHERE c.id_materia = ?;
  `;

  pool.query(query, [materiaId], (err, results) => {
    if (err) {
      console.error('Error al obtener las clases:', err.stack);
      return res.status(500).json({ message: 'Error al obtener las clases' });
    }

    res.json(results);
  });
});
//obtener alumnos de una materia
app.get('/materias/:idMateria/alumnos', async (req, res) => {
  const { idMateria } = req.params;
  try {
    const query = `
      SELECT u.id, u.nombre, u.correo 
      FROM usuario_materia um
      JOIN usuario u ON um.usuario_id = u.id
      WHERE um.materia_id = ?`;
    pool.query(query, [idMateria], (err, results) => {
      if (err) {
        console.error('Error en la consulta:', err.stack);
        return res.status(500).send('Error en la consulta');
      }
      res.json({ alumnos: results });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener los alumnos de la materia' });
  }
});
// Obtener alumnos de una clase
app.get('/clases/:idClase/alumnos', async (req, res) => {
  const { idClase } = req.params;
  try {
    const query = `
      SELECT u.id, u.nombre, u.correo, a.id_tp_asistencia
      FROM asistencia a
      JOIN usuario u ON a.id_usuario = u.id
      WHERE a.id_clase = ?`;
    
    pool.query(query, [idClase], (err, results) => {
      if (err) {
        console.error('Error en la consulta:', err.stack);
        return res.status(500).send('Error en la consulta');
      }
      res.json({ alumnos: results });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener los alumnos de la clase' });
  }
});
//Endpoint que utilizaré para actualizar la asistencia
router.post('/update-asistencia', (req, res) => {
  const { id_clase, id_usuario } = req.body;

  if (!id_clase || !id_usuario) {
    return res.status(400).json({ error: 'Faltan parámetros' });
  }

  // Aquí actualizamos el id_tp_asistencia
  const query = 'UPDATE asistencia SET id_tp_asistencia = 2 WHERE id_clase = ? AND id_usuario = ?';
  
  db.query(query, [id_clase, id_usuario], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Error al actualizar la asistencia' });
    }
    res.status(200).json({ message: 'Asistencia actualizada correctamente' });
  });
});
app.listen(port, () => {
  console.log(`Servidor en funcionamiento en http://0.0.0.0:${port}`);
});
