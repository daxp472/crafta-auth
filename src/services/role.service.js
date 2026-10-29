const Role = require('../models/role');
const ApiError = require('../utils/api-error');

class RoleService {
  async createRole(roleData) {
    const existing = await Role.findOne({ name: roleData.name });
    if (existing) {
      throw ApiError.conflict(`Role "${roleData.name}" already exists`);
    }
    const role = new Role(roleData);
    await role.save();
    return role;
  }

  async getRoleByName(name) {
    return Role.findOne({ name });
  }

  async updateRole(name, updates) {
    return Role.findOneAndUpdate(
      { name },
      updates,
      { new: true, runValidators: true }
    );
  }

  async deleteRole(name) {
    const role = await Role.findOne({ name });
    if (role.isSystem) {
      throw new Error('Cannot delete system role');
    }
    await role.remove();
  }

  async assignPermissions(roleName, permissions) {
    const role = await Role.findOne({ name: roleName });
    role.permissions = permissions;
    await role.save();
    return role;
  }

  async checkPermission(role, resource, action) {
    const roleDoc = await Role.findOne({ name: role });
    if (!roleDoc) return false;

    return roleDoc.permissions.some(p => 
      p.resource === resource && 
      (p.actions.includes(action) || p.actions.includes('manage'))
    );
  }
}

module.exports = RoleService;