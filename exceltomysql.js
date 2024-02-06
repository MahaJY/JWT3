const express = require('express');
const ExcelJS = require('exceljs');
const bcrypt = require('bcrypt');
const { Sequelize, DataTypes } = require('sequelize');
const path = require('path');
const app = express();
const port = 3011;
const sequelize = new Sequelize('world', 'root', 'root555', {
  host: 'localhost',
  dialect: 'mysql',
});
const User = sequelize.define('employeedetails', {
  id: {
    type: DataTypes.STRING,
    primaryKey: true,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  jobtitle: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  department: { type: DataTypes.STRING },
  username: { type: DataTypes.STRING },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  role: DataTypes.STRING,
}, {
  timestamps: false,
  tableName: 'employeedetails',
});
app.use(express.json());
app.post('/upload', async (req, res) => {
  try {
    const filePath = req.body.filePath;  // "filePath":"C:\\Users\\Asus\\Desktop\\nodejs_pratice\\Book2.xlsx"

    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.readFile(filePath);

    const worksheet = workbook.getWorksheet(1);

    await worksheet.eachRow({ includeEmpty: false }, async (row, rowNumber) => {
      if (rowNumber > 1) {
      const data = row.values;
      console.log('Row values:', data);
      if (data[1] && data[2] && data[3] && data[4] && data[5] && data[6]) {
        const hashedPassword = bcrypt.hashSync(data[6], 10);
        await User.create({
          id: data[1],
          name: data[2],
          jobtitle: data[3],
          department: data[4],
          username: data[5],
          password: hashedPassword,
          role: data[7],
        });
      } else {
        console.error('Incomplete data in Excel row:', data);
      }}
    });
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
