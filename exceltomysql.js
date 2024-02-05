const express = require('express');
const ExcelJS = require('exceljs');
const bcrypt = require('bcrypt');
const { Sequelize, DataTypes } = require('sequelize');
const path = require('path');
const app = express();
const port = 3002;
const sequelize = new Sequelize('world', 'root', 'root555', {
  host: 'localhost',
  dialect: 'mysql',
});
const User = sequelize.define('empdetailss', {
  name: DataTypes.STRING,
  jobtitle: DataTypes.STRING,
  Department: DataTypes.STRING,
  username: DataTypes.STRING,
  password: DataTypes.STRING,
  role: DataTypes.STRING,
});
app.use(express.json());
app.post('/upload', async (req, res) => {
  try {
    const filePath = req.body.filePath;

    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.readFile(filePath); 

    const worksheet = workbook.getWorksheet(1);

    for (const row of worksheet.getRows()) {
      const { name, jobtitle, Department, username, password, role } = row.values;
      const hashedPassword = bcrypt.hashSync(password, 10);
      await User.create({
        name,
        jobtitle,
        Department,
        username,
        password: hashedPassword,
        role,
      });
    }

    return res.status(200).json({ message: 'Data imported successfully' });
  } catch (error) {
    console.error('Error importing data:', error.message);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});
sequelize.sync().then(() => {
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
});