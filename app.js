const express = require('express');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/authroutes');
const sequelize = require('./config/db');
const app = express();
app.use(bodyParser.json());
app.use('/emp', authRoutes);
sequelize.sync().then(() => {
    const PORT = 2013;
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  });