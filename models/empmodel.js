const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');
const bcrypt = require('bcrypt');

const UserAuth = sequelize.define('emp', {
  id:{
    type:DataTypes.INTEGER,
    primaryKey:true,
    autoIncrement:true,
  },
  name:{
    type:DataTypes.STRING,
    allowNull:false,
  },
  age: {
    type: DataTypes.INTEGER,
  },
  email: {
    type: DataTypes.STRING,
  },
  username: {
    type: DataTypes.STRING,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
    set(value) {
      // Hash the password before saving to the database
      const hashedPassword = bcrypt.hashSync(value, 10);
      this.setDataValue('password', hashedPassword);
    }},
  role:{
    type: DataTypes.STRING,
  }
}, {
  timestamps: false,
  tableName:'emp',
});

module.exports = UserAuth;