var mongoose = require('mongoose');
var bcryptNodeJs = require('bcrypt-nodejs');

var userSchema = new mongoose.Schema({
   local: {
       username: String,
       password: String
   },

    facebook: {
        id: String,
        token: String,
        email: String,
        name: String
    }
});

userSchema.methods.generateHash = function (password) {
    return bcryptNodeJs.hashSync(password, bcryptNodeJs.genSaltSync(8), null);
};

userSchema.methods.validPassword = function (password) {
    return bcryptNodeJs.compareSync(password, this.local.password);
};

module.exports = mongoose.model('User', userSchema);