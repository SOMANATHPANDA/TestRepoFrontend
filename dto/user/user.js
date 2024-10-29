class UserDTO {
  constructor(user) {
    this._id = user._id;
    this.firstName = user.firstName;
    this.lastName = user.lastName;
    this.email = user.email;
    this.age = user.age;
    this.address = user.address;
  }
}
module.exports = UserDTO;
