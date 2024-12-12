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
// Ruta para crear una nueva clase y registrar la asistencia
app.post('/registrar-asistencia', (req, res) => {
  const { idClase, idMateria } = req.body;

  // Validar que se proporcionen los datos necesarios
  if (!idClase || !idMateria) {
    return res.status(400).json({ message: 'Por favor, proporciona el id de la clase y el id de la materia' });
  }

  // Verificar si la clase existe
  pool.query('SELECT * FROM clases WHERE id_clase = ?', [idClase], (err, claseResults) => {
    if (err) {
      console.error('Error al verificar la clase:', err.stack);
      return res.status(500).json({ message: 'Error al verificar la clase' });
    }

    if (claseResults.length === 0) {
      return res.status(404).json({ message: 'Clase no encontrada' });
    }

    // Obtener la lista de alumnos asociados a la materia
    pool.query(
      `SELECT u.id AS id_usuario, u.nombre AS nombre_usuario
       FROM usuario_materia um
       JOIN usuario u ON um.usuario_id = u.id
       WHERE um.materia_id = ?`,
      [idMateria],
      (err, alumnosResults) => {
        if (err) {
          console.error('Error al obtener los alumnos:', err.stack);
          return res.status(500).json({ message: 'Error al obtener los alumnos' });
        }

        if (alumnosResults.length === 0) {
          return res.status(404).json({ message: 'No hay alumnos asociados a esta materia' });
        }

        // Preparar los valores para insertar en la tabla asistencia
        const asistenciaValues = alumnosResults.map((alumno) => [
          alumno.id_usuario, // id_usuario
          idClase,           // id_clase
          idMateria,         // id_materia
          alumno.nombre_usuario, // nombre_usuario
          2                  // id_tp_asistencia (default)
        ]);

        // Insertar registros de asistencia en la tabla
        pool.query(
          'INSERT INTO asistencia (id_usuario, id_clase, id_materia, nombre_usuario, id_tp_asistencia) VALUES ?',
          [asistenciaValues],
          (err) => {
            if (err) {
              console.error('Error al registrar asistencia:', err.stack);
              return res.status(500).json({ message: 'Error al registrar asistencia' });
            }

            res.status(201).json({
              message: 'Asistencia registrada exitosamente',
              totalAsistencias: asistenciaValues.length
            });
          }
        );
      }
    );
  });
});



// Función para generar un ID aleatorio de 6 caracteres
function generateRandomID() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let randomID = '';
  for (let i = 0; i < 6; i++) {
    randomID += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return randomID;
}
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

app.listen(port, () => {
  console.log(`Servidor en funcionamiento en http://0.0.0.0:${port}`);
});
