/**
 * This is code to manage database migrations for the TrustAuth addon.
 *
 * @author Daniel Fox
 * @link trustauth.com
 * @license BSD-3 Clause License http://opensource.org/licenses/BSD-3-Clause
 *
 * Copyright (c) 2012, Daniel Fox
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 *     Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *     Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *     Neither the name of TrustAuth nor the names of its contributors may be used to endorse or promote products derived from this software
 *         without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
var EXPORTED_SYMBOLS = [ 'Manager', 'BASE_VERSION' ];

/*
 * Since this code can probably seem a little overwhelming at first, here is an example of how to use this Migration Manager.
 *
 * var db = {
 *   version: BASE_VERSION,
 *   get_version: function() { return this.version; },
 *   set_version: function(version) { this.version = version; },
 *
 *   // Other code to handle a database
 *   ...
 * };
 * var manager = Manager(db);
 *
 * manager.add_migration("Create data table", {
 *   up: function(db) {
 *     db.execute_sql("CREATE TABLE data(id INTEGER PRIMARY KEY, field TEXT);");
 *   },
 *   down: function(db) {
 *     db.execute_sql("DROP TABLE data;");
 * }});
 *
 * manager.migrate();
 *
 * This format allows abstract functions to be written that return the hash such as:
 *
 * function create_table(name, columns) {
 *   return {
 *     up: function(db) { db.executeSimpleSQL("CREATE TABLE " + name + " (" + columns + ")"); },
 *     down: function(db) { db.executeSimpleSQL("DROP TABLE " + name) },
 *   };
 * }
 */

const BASE_VERSION = 0;

/**
 * This is the factory function used to create migrations. Your migrations are created using this or the
 * Manager.add_migration() function.
 */
function Migration(version_number, name, up, down) {
  return {
    version_number: version_number,
    name: name,

    up: up,
    down: down,
  };
}

/**
 * The object returned by this factory function is the migration manager. It manages what version
 * the database is currently at and the list of migrations that have been created. It can migrate
 * up, down, and to specific version numbers.
 *
 * @param {object} db This is the object encapsulating the database. It needs to have these functions defined
 *   in order to be used with this manager.
 *
 *   get_version() - returns the current version number of database. To prevent the manager from hitting the
 *                   database every call this should be cached by the db object.
 *   set_version(version) - sets the current version number of the database.
 *   reset() - this function must return the database to the original state before any migrations were run. It
 *             can be used to fix a database that has gotten stuck from bad down functions in migrations.
 */
function Manager(db) {
  return {
    _latest_version : BASE_VERSION, // This is the maximum version number or in other words the version number of the last migration.
    _current_version: function() { return this._db.get_version(); },     // This version that the database is currently at.
    _next_version   : function() { return this._db.get_version() + 1; }, // This is the version number of the next migration.

    _db        : db, // This is the database object that this manager is managing.
    _migrations: [], // This is the list of migrations currently in this manager.

    migration_count: function() { return this._migrations.length }, // This is the number of migrations in the manager.

    /**
     * This function adds a new migration to the manager with cooresponding up and down functions.
     *
     * NOTE: Both functions passed in should return true if successful or false if there was an error. This lets the manager
     * stop running migrations and alert the code running the migration.
     *
     * Example functions hash: { up: function(db) { return true; }, down: function(db) { return true; } }
     *
     * @param {string} name the name for you to identify this migration with if an error occurs
     * @param {hash} functions a hash containing 'up' and 'down' functions that take the database object as a parameter and returns a success bool
     * @return {bool} true if the migration was added, false if there was an error
     */
    add_migration: function(name, functions) {
      if ( ! this._isset(functions) || ! this._isset(functions['up']) || ! this._isset(functions['down'])) { return false; }
      this._migrations.push(Migration(++(this._latest_version), name, functions['up'], functions['down']));
      return true;
    },

    _isset: function(variable) {
      return (variable !== null && typeof variable !== "undefined");
    },

    /**
     * This function migrates the database to the latest version from whatever version it is currently on.
     *
     * @return {bool} true if successful, false if there was an error
     */
    migrate: function() {
      var error = false;
      while(this._current_version() < this._latest_version) {
        error = error || this._up(this._migrations[this._current_version()]);
      }
      return !error;
    },

    /**
     * This function migrates the database to a specific version number. It will stop at the BASE_VERSION or latest_version.
     *
     * @param {int} version_number the version to stop at
     * @return {bool} true if successful, false if there was an error
     */
    migrate_to_version: function(version_number) {
      if(version_number > this._latest_version) { this.migrate(); } // Might as well migrate since we're going to the latest version anyways.
      if(version_number <= BASE_VERSION) { this.reset(); } // Might as well reset since we're undoing all migrations anyways.

      if(version_number > this._current_version()) {
        return this.up(version_number - this._current_version());
      } else if(version_number < this._current_version()) {
        return this.down(this._current_version() - version_number);
      } else {
        // Do nothing because we're at that version number
        return true;
      }
    },

    /**
     * This function migrates the database up count migrations stopping at the latest_version if it would otherwise go past.
     *
     * @param {int} count the number of migrations to go up.
     * @return {bool} true on success, false if there was an error.
     */
    up: function(count) {
      var result = true;
      for(var i = 0; i < count; i++) {
        if(this._current_version() < this._latest_version) {
          result = result && this._up(this._migrations[this._next_version()]);
        }
      }
      return result;
    },

    /**
     * This function migrates the database down count migrations stopping at the BASE_VERSION if it would otherwise go past.
     *
     * @param {int} count the number of migrations to go down.
     * @return {bool} true on success, false if there was an error.
     */
    down: function(count) {
      var result = true;
      for(var i = 0; i < count; i++) {
        if(this._current_version() > 0) {
          result = result && this._down(this._migrations[this._current_version()]);
        }
      }
      return result;
    },

    /**
     * This function migrates down count migrations and then migrates back up count migrations.
     *
     * NOTE: If count is large enough to take current_version below or equal to BASE_VERSION then when the database is
     * migrated back up it will be higher up than it was prior to running this function.
     *
     * @param {int} count the number of migrations to redo
     * @return {bool} true on success, false if there was an error
     */
    redo: function(count) {
      return this.down(count) && this.up(count);
    },

    /**
     * This function rolls back the most recent migration.
     *
     * @return {bool} true on success, false if there was an error
     */
    rollback: function() {
      return this.down(1);
    },

    /**
     * This function resets the database to its original state before any migrations were run.
     *
     * @return {bool} true if successful, false if there was an error
     */
    reset: function() {
      this._db.reset();
    },

    /**
     * This function is a private function to wrap a single migration up.
     *
     * @param {Migration} migration the migration object to run up on
     * @return {bool} true if successful, false if there was an error
     */
    _up: function(migration) {
      if(migration.up(this._db)) {
        this._db.set_version(migration.version_number);
        return true;
      } else {
        throw "Failed on up for migration with the name " + migration.name + " and version number " + migration.version_number;
        return false;
      }
    },

    /**
     * This function is a private function to wrap a single migration down.
     *
     * @param {Migration} migration the migration object to run down on
     * @return {bool} true if successful, false if there was an error
     */
    _down: function(migration) {
      if(migration.down(this._db)) {
        this._db.set_version(migration.version_number - 1);
        return true;
      } else {
        throw "Failed on down for migration with the name " + migration.name + " and version number " + migration.version_number;
        return false;
      }
    },
  };
}
