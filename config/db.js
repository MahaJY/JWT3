const { Sequelize } = require('sequelize');
const sequelize = new Sequelize('world', 'root', 'root555', {
  host: 'localhost',
  dialect: 'mysql',
});
module.exports = sequelize;