// Módulos necesarios
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise'); // Cambiado a mysql2/promise
const bcrypt = require('bcryptjs');

// Instancia express
const app = express();
const port = process.env.PORT || 3000;

// Configuración del middleware CORS
app.use(cors({
  origin: 'http://localhost:8100', // Cambia esto según tu entorno
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware para parsear JSON
app.use(express.json());

// Crear un pool de conexiones usando mysql2/promise
const pool = mysql.createPool({
  host: process.env.DB_SERVER,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,  // Ajusta el límite de conexiones según lo necesites
  queueLimit: 0
});

// Endpoint para login
app.post('/login', async (req, res) => {
  const { correo, password } = req.body;
  
  if (!correo || !password) {
    return res.status(400).json({ message: 'Por favor, proporciona correo y contraseña' });
  }
  
  try {
    const [results] = await pool.query('SELECT id, nombre, id_tp_usuario, contrasena FROM usuario WHERE correo = ?', [correo]);

    if (results.length > 0) {
      const isMatch = await bcrypt.compare(password, results[0].contrasena);

      if (isMatch) {
        return res.json({
          valid: true,
          id: results[0].id,
          nombre: results[0].nombre,
          id_tp_usuario: results[0].id_tp_usuario
        });
      } else {
        return res.json({ valid: false });
      }
    } else {
      return res.json({ valid: false });
    }
  } catch (err) {
    console.error('Error en la consulta o verificación de contraseña:', err);
    return res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Endpoint para registrar un nuevo usuario
app.post('/registro', async (req, res) => {
  const { nombre, correo, contrasena } = req.body;
  
  if (!nombre || !correo || !contrasena) {
    return res.status(400).json({ error: 'Todos los campos son requeridos.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(contrasena, 10);
    const query = 'INSERT INTO usuario (correo, nombre, contrasena, id_tp_usuario) VALUES (?, ?, ?, 1)';
    await pool.query(query, [correo, nombre, hashedPassword]);

    res.status(201).json({ message: 'Usuario fue registrado con éxito.' });
  } catch (error) {
    console.error('Error al registrar el usuario:', error);
    res.status(500).json({ error: 'Correo ya registrado, recupera tu contraseña' });
  }
});

// Ruta para verificar si el correo existe
app.post('/validar-correo', async (req, res) => {
  const { correo } = req.body;
  
  try {
    const [results] = await pool.query('SELECT * FROM usuario WHERE correo = ?', [correo]);
    res.json({ existe: results.length > 0 });
  } catch (err) {
    console.error('Error en la consulta:', err.stack);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Ruta para cambiar la contraseña
app.post('/cambiar-contrasena', async (req, res) => {
  const { correo, nuevaContrasena } = req.body;

  if (!correo || !nuevaContrasena) {
    return res.status(400).json({ message: 'Por favor, proporciona el correo y la nueva contraseña' });
  }

  try {
    const hashedPassword = await bcrypt.hash(nuevaContrasena, 10);
    const [result] = await pool.query('UPDATE usuario SET contrasena = ? WHERE correo = ?', [hashedPassword, correo]);

    if (result.affectedRows > 0) {
      res.json({ message: 'Contraseña cambiada exitosamente' });
    } else {
      res.status(404).json({ message: 'Correo no registrado' });
    }
  } catch (err) {
    console.error('Error al cambiar la contraseña:', err);
    res.status(500).json({ message: 'Error al cambiar la contraseña' });
  }
});

// Ruta para obtener todos los usuarios
app.get('/usuarios', async (req, res) => {
  try {
    const [results] = await pool.query('SELECT * FROM usuario');
    res.json(results);
  } catch (err) {
    console.error('Error en la consulta:', err.stack);
    res.status(500).send('Error en la consulta');
  }
});

// Endpoint para obtener las materias asociadas a un usuario
app.get('/materias/usuario/:usuarioId', async (req, res) => {
  const { usuarioId } = req.params;

  if (!usuarioId) {
    return res.status(400).json({ message: 'Por favor, proporciona un usuarioId' });
  }

  try {
    const query = `
      SELECT um.materia_id, m.nombre, m.descripcion 
      FROM usuario_materia um 
      INNER JOIN materias m ON um.materia_id = m.id 
      WHERE um.usuario_id = ?;
    `;

    const [results] = await pool.query(query, [usuarioId]);
    res.json(results);
  } catch (err) {
    console.error('Error al obtener las materias:', err.stack);
    res.status(500).json({ message: 'Error al obtener las materias' });
  }
});

// Endpoint para obtener todas las materias
app.get('/materias', async (req, res) => {
  try {
    const [results] = await pool.query('SELECT * FROM materias');
    res.json(results);
  } catch (err) {
    console.error('Error en la consulta:', err.stack);
    res.status(500).send('Error en la consulta');
  }
});

// Ruta para crear una nueva clase
app.post('/crear-clase', async (req, res) => {
  const { idMateria } = req.body;

  if (!idMateria) {
    return res.status(400).json({ message: 'Por favor, proporciona el id de la materia' });
  }

  try {
    // Obtener el nombre de la materia
    const [materias] = await pool.query('SELECT nombre FROM materias WHERE id = ?', [idMateria]);

    if (materias.length === 0) {
      return res.status(404).json({ message: 'Materia no encontrada' });
    }

    const nombreMateria = materias[0].nombre;

    // Contar las clases existentes para esta materia
    const [clasesCount] = await pool.query('SELECT COUNT(*) AS totalClases FROM clases WHERE id_materia = ?', [idMateria]);
    const claseNumero = clasesCount[0].totalClases + 1;

    // Generar el nombre y el ID de la nueva clase
    const nombreClase = `${nombreMateria} clase ${claseNumero}`;
    const idClase = Math.random().toString(36).substring(2, 8).toUpperCase();
    const fechaCreacion = new Date();

    // Insertar la nueva clase
    await pool.query(
      'INSERT INTO clases (id_clase, id_materia, nombre, fecha_creacion) VALUES (?, ?, ?, ?)',
      [idClase, idMateria, nombreClase, fechaCreacion]
    );

    res.status(201).json({
      message: 'Clase creada exitosamente',
      idClase: idClase,
      nombreClase: nombreClase
    });
  } catch (err) {
    console.error('Error al crear la clase:', err.stack);
    res.status(500).json({ message: 'Error al crear la clase' });
  }
});

// Ruta para obtener todas las clases de una materia específica
app.get('/clases/materia/:materiaId', async (req, res) => {
  const { materiaId } = req.params;

  if (!materiaId) {
    return res.status(400).json({ message: 'Por favor, proporciona un materiaId' });
  }

  try {
    const query = `
      SELECT c.id_materia, c.id_clase, c.nombre, c.fecha_creacion 
      FROM clases c
      WHERE c.id_materia = ?;
    `;

    const [results] = await pool.query(query, [materiaId]);
    res.json(results);
  } catch (err) {
    console.error('Error al obtener las clases:', err.stack);
    res.status(500).json({ message: 'Error al obtener las clases.' });
  }
});

// Obtener alumnos de una materia
app.get('/materias/:idMateria/alumnos', async (req, res) => {
  const { idMateria } = req.params;

  if (!idMateria) {
    return res.status(400).json({ message: 'Por favor, proporciona un idMateria válido.' });
  }

  try {
    const query = `
      SELECT u.id, u.nombre, u.correo 
      FROM usuario_materia um
      JOIN usuario u ON um.usuario_id = u.id
      WHERE um.materia_id = ?`;
    
    const [results] = await pool.query(query, [idMateria]);
    res.json({ alumnos: results });
  } catch (err) {
    console.error('Error en la consulta:', err.stack);
    res.status(500).json({ message: 'Error al obtener los alumnos de la materia' });
  }
});

// Obtener alumnos de una clase
app.get('/clases/:idClase/alumnos', async (req, res) => {
  const { idClase } = req.params;

  if (!idClase) {
    return res.status(400).json({ message: 'Por favor, proporciona un idClase válido.' });
  }

  try {
    const query = `
      SELECT u.id, u.nombre, u.correo, a.id_tp_asistencia
      FROM asistencia a
      JOIN usuario u ON a.id_usuario = u.id
      WHERE a.id_clase = ?`;
    
    const [results] = await pool.query(query, [idClase]);
    res.json({ alumnos: results });
  } catch (err) {
    console.error('Error en la consulta:', err.stack);
    res.status(500).json({ error: 'Error al obtener los alumnos de la clase' });
  }
});

// Endpoint para actualizar la asistencia
app.options('/update-asistencia', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.status(204).send();
});

app.post('/update-asistencia', async (req, res) => {
  console.log('Solicitud POST recibida:', req.body);

  const { id_clase, id_usuario } = req.body;

  if (!id_clase || !id_usuario) {
    console.error('Faltan parámetros:', req.body);
    return res.status(400).json({ error: 'Faltan parámetros' });
  }

  try {
    const query = 'UPDATE asistencia SET id_tp_asistencia = 1 WHERE id_clase = ? AND id_usuario = ?';
    const [result] = await pool.query(query, [id_clase, id_usuario]);

    if (result.affectedRows === 0) {
      console.warn('No se encontró el registro para actualizar');
      return res.status(404).json({ error: 'No se encontró la clase o el usuario para actualizar' });
    }

    res.status(200).json({ message: 'Asistencia actualizada correctamente' });
  } catch (err) {
    console.error('Error al actualizar la asistencia:', err);
    res.status(500).json({ error: 'Error al actualizar la asistencia' });
  }
});

// Método para contar clases y asistencias
app.get('/conteo-asistencia/:usuarioId', async (req, res) => {
  const { usuarioId } = req.params;

  if (!usuarioId) {
    return res.status(400).json({ message: 'Por favor, proporciona un usuarioId válido.' });
  }

  try {
    const queryMaterias = `
      SELECT um.materia_id, m.nombre AS materia_nombre, m.descripcion
      FROM usuario_materia um
      INNER JOIN materias m ON um.materia_id = m.id
      WHERE um.usuario_id = ?;
    `;

    const [materias] = await pool.query(queryMaterias, [usuarioId]);

    const queryClases = `
      SELECT 
        c.id_materia AS materia_id,
        COUNT(DISTINCT c.id_clase) AS total_clases,
        SUM(CASE WHEN a.id_tp_asistencia = 1 THEN 1 ELSE 0 END) AS total_asistencias
      FROM clases c
      LEFT JOIN asistencia a 
        ON c.id_clase = a.id_clase AND a.id_usuario = ?
      WHERE c.id_materia IN (SELECT materia_id FROM usuario_materia WHERE usuario_id = ?)
      GROUP BY c.id_materia;
    `;

    const [clases] = await pool.query(queryClases, [usuarioId, usuarioId]);

    const resultado = materias.map((materia) => {
      const claseData = clases.find((clase) => clase.materia_id === materia.materia_id);

      return {
        materia_id: materia.materia_id,
        materia_nombre: materia.materia_nombre,
        descripcion: materia.descripcion,
        total_clases: claseData?.total_clases || 0,
        total_asistencias: claseData?.total_asistencias || 0,
      };
    });

    res.json(resultado);
  } catch (error) {
    console.error('Error al contar clases y asistencias:', error);
    res.status(500).json({ error: 'Error al contar clases y asistencias' });
  }
});

// Ver clases faltantes del estudiante
app.get('/clases-faltantes/:usuarioId', async (req, res) => {
  const { usuarioId } = req.params;
  const { materiaId } = req.query;

  if (!usuarioId || !materiaId) {
    return res.status(400).json({ message: 'UsuarioId y materiaId son requeridos.' });
  }

  try {
    const queryClasesFaltantes = `
      SELECT c.id_clase, c.nombre AS clase_nombre, c.fecha_creacion
      FROM clases c
      LEFT JOIN asistencia a 
        ON c.id_clase = a.id_clase AND a.id_usuario = ?
      WHERE c.id_materia = ? AND (a.id_tp_asistencia IS NULL OR a.id_tp_asistencia != 1);
    `;

    const [clasesFaltantes] = await pool.query(queryClasesFaltantes, [usuarioId, materiaId]);
    res.json(clasesFaltantes);
  } catch (err) {
    console.error('Error al obtener las clases faltantes:', err);
    res.status(500).json({ message: 'Error al obtener las clases faltantes.' });
  }
});

// Endpoint para eliminar el usuario
app.delete('/usuarios/:id', async (req, res) => {
  const { id } = req.params;
  let connection;

  console.log(`Recibiendo solicitud para eliminar usuario con ID: ${id}`);

  try {
    // Obtener una conexión del pool
    connection = await pool.getConnection();
    console.log('Conexión a la base de datos establecida.');

    // Iniciar la transacción
    await connection.beginTransaction();
    console.log('Transacción iniciada.');

    // Eliminar el usuario (los triggers manejarán las relaciones)
    await connection.query('DELETE FROM usuario WHERE id = ?', [id]);
    console.log(`Usuario con ID ${id} eliminado de la tabla 'usuario'.`);

    // Confirmar la transacción
    await connection.commit();
    console.log('Transacción confirmada.');

    res.status(200).json({ message: `Usuario con ID ${id} eliminado correctamente.` });
  } catch (err) {
    if (connection) {
      try {
        // Revertir la transacción en caso de error
        await connection.rollback();
        console.log('Transacción revertida debido a un error.');
      } catch (rollbackErr) {
        console.error('Error al revertir la transacción:', rollbackErr);
      }
    }
    console.error('Error al eliminar usuario:', err);
    res.status(500).json({ message: 'Error al eliminar el usuario.' });
  } finally {
    if (connection) {
      // Liberar la conexión
      connection.release();
      console.log('Conexión liberada.');
    }
  }
});
// Endpoint para asignar materias a un usuario con validación de duplicados
app.post('/asignar-materias', async (req, res) => {
  const { usuarioId, materias } = req.body;

  if (!usuarioId || !Array.isArray(materias) || materias.length === 0) {
    return res.status(400).json({ message: 'Datos inválidos. Verifica el usuarioId y las materias.' });
  }

  let connection;

  try {
    connection = await pool.getConnection();

    // Iniciar una transacción
    await connection.beginTransaction();

    // Insertar las materias para el usuario, evitando duplicados
    const existeQuery = 'SELECT COUNT(*) AS total FROM usuario_materia WHERE usuario_id = ? AND materia_id = ?';
    const insertQuery = 'INSERT INTO usuario_materia (usuario_id, materia_id) VALUES (?, ?)';

    for (const materiaId of materias) {
      const [result] = await connection.query(existeQuery, [usuarioId, materiaId]);

      if (result[0].total > 0) {
        console.log(`La materia con ID ${materiaId} ya está asignada al usuario ${usuarioId}.`);
        continue; // Saltar si ya está asignada
      }

      await connection.query(insertQuery, [usuarioId, materiaId]);
    }

    // Confirmar la transacción
    await connection.commit();

    res.status(201).json({ message: 'Materias asignadas exitosamente.' });
  } catch (error) {
    if (connection) await connection.rollback(); // Revertir en caso de error
    console.error('Error al asignar materias:', error);
    res.status(500).json({ message: 'Error al asignar materias.' });
  } finally {
    if (connection) connection.release(); // Liberar conexión
  }
});
//endpoint para remover las materias de un alumo
app.post('/remover-materias', async (req, res) => {
  const { usuarioId, materiasIds } = req.body;

  // Validar que los datos necesarios están presentes
  if (!usuarioId || !Array.isArray(materiasIds) || materiasIds.length === 0) {
    return res.status(400).json({ message: 'UsuarioId y materiasIds son requeridos, y materiasIds debe ser un array no vacío.' });
  }

  try {
    // Ejecutar la consulta SQL
    const query = `DELETE FROM usuario_materia WHERE usuario_id = ? AND materia_id IN (?)`;
    await pool.query(query, [usuarioId, materiasIds]);

    // Responder con éxito
    res.json({ message: 'Materias removidas con éxito.' });
  } catch (error) {
    console.error('Error al remover materias:', error);

    // Responder con un mensaje de error
    res.status(500).json({ message: 'Error al remover materias.' });
  }
});
// Iniciar el servidor
app.listen(port, '0.0.0.0', () => {
  console.log(`Servidor en funcionamiento en http://0.0.0.0:${port}`);
});
