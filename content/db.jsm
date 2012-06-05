/**
 * This is the database code for the TrustAuth addon. This is browser specific code.
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
var EXPORTED_SYMBOLS = [ 'db' ];

Components.utils.import("chrome://trustauth/content/utils.jsm");
Components.utils.import("chrome://trustauth/content/constants.jsm");
Components.utils.import("chrome://trustauth/content/crypto.jsm");
Components.utils.import("chrome://trustauth/content/migrations.jsm");

var db = {
  version: null,
  manager: null,

  /**
   * Associates the given key id with the given domain id. This function fails if the key is
   * already assigned to another domain.
   *
   * @param {integer} key_id the key id to associate this domain to
   * @param {integer} site_id the id of the domain to associate this key to
   * @return {bool} true if successful; false otherwise
   */
  associate_key: function(key_id, site_id) {
    // If this key is available then assign it to this domain
    return ! this.is_key_assigned(key_id) &&
      this._execute("INSERT INTO keys_sites (key_id, site_id) VALUES(:key_id, :site_id)", function(statement) {
        statement.params.key_id  = key_id;
        statement.params.site_id = site_id;
        statement.execute();
        utils.log('key associated successfully');
      });
  },

  /*
   * Connects to the database.
   */
  connect: function() {
    Components.utils.import("resource://gre/modules/Services.jsm");
    Components.utils.import("resource://gre/modules/FileUtils.jsm");

    // Establish a connection to the database
    var file = FileUtils.getFile("ProfD", ["trustauth", "trustauth.sqlite"]);
    var file_exists = file.exists();
    return Services.storage.openDatabase(file);
  },

  count_cache_keys: function() {
    var count = null;
    this._execute("SELECT COUNT(id) as count_id FROM keys WHERE id not in (SELECT key_id FROM keys_sites)", function(statement) {
      if (statement.executeStep()) {
        count = statement.row.count_id;
      }
    });
    return count;
  },

  /*
   * Checks to see if the given domain has a key in the database
   *
   * @param domain the domain to look for
   * @return true if the domain is in the database false otherwise
   */
  domain_exist: function(domain) {
    var domain_exists = false;
    this._execute("SELECT domain " +
                  "FROM keys, sites, keys_sites " +
                  "WHERE keys.id=keys_sites.key_id AND sites.id=keys_sites.site_id AND sites.domain=:domain " +
                  "ORDER BY keys.created DESC", function(statement) {
      statement.params.domain = domain;
      if (statement.executeStep()) {
        domain_exists = domain === statement.row.domain;
      }
     });
    return domain_exists;
  },

  /**
   * Fetches the first cached key id from the database.
   */
  fetch_cache_id: function() {
    var key_id = null;
    this._execute("SELECT id FROM keys WHERE id not in (SELECT key_id FROM keys_sites) LIMIT 1", function(statement) {
      if (statement.executeStep()) {
        key_id = statement.row.id;
      }
    });
    return key_id;
  },

  /*
   * Fetches the most recently created key pair for the given domain, decrypts them
   * using the encryption key and returns the pair as a hash.
   *
   * @param domain the domain to fetch keys for
   * @return hash of the public and private key pair or null if the domain doesn't have a key pair
   */
  fetch_key_pair: function(domain) {
    var key_pair = null;
    this._execute("SELECT k.id, public_key, private_key " +
                  "FROM keys as k, sites as s, keys_sites as ks " +
                  "WHERE k.id=ks.key_id AND s.id=ks.site_id AND s.domain=:domain " +
                  "ORDER BY k.created DESC", function(statement) {
      statement.params.domain = domain;
      if (statement.executeStep()) {
        key_pair = {
          'id': statement.row.id,
          'public_key': statement.row.public_key,
          'private_key': statement.row.private_key,
        };
      } else {
        utils.log("could not find key_pair for domain: " + domain);
      }
    });
    return key_pair;
  },

  /**
   * Adds the domain name to the database and returns the site_id of the domain.
   *
   * @param {string} domain the domain name to add
   * @return {integer} the id of the either the new domain or the previously inserted domain
   */
  fetch_or_store_domain: function(domain) {
    // First try to insert the domain if it's not already there.
    var site_id = this.get_site_id(domain);
    if (site_id === null) {
      this._execute("INSERT INTO sites (domain) VALUES(:domain)", function(statement, db) {
        statement.params.domain = domain;
        statement.execute();
        site_id = db.lastInsertRowID;
      });
    }
    return site_id;
  },

  /**
   * Retrieves the hash stored in the database.
   *
   * @return {string} the hash if there is one, null otherwise
   */
  get_stored_hash: function() {
    var hash = null;
    this._execute("SELECT hash FROM password_verify LIMIT 1", function(statement) {
      if (statement.executeStep()) {
        hash = statement.row.hash;
      }
    });
    return hash;
  },

  /*
   * Returns the site_id for the domain or null if the domain wasn't found.
   *
   * @param domain the domain to get the site_id for
   * @return the site_id
   */
  get_site_id: function(domain) {
    var row_id = null;
    this._execute("SELECT id FROM sites WHERE domain=:domain", function(statement) {
      statement.params.domain = domain;
      if (statement.executeStep()) {
        row_id = statement.row.id;
      }
    });
    return row_id;
  },

  /*
   * Returns a hash of the encryption key that is safe to store for
   * password verification.
   *
   * @param encryption_key the key to get a storage hash of
   * @return the hash of the key
   */
  get_storage_hash: function(encryption_key) {
    return utils.sha256(encryption_key + TRUSTAUTH_STORAGE_SALT);
  },

  /**
   * Returns the current database version number of the database. The version
   * is cached to avoid querying each call.
   *
   * @return {int} the current migration version of the database
   */
  get_version: function() {
    return this.version;
  },

  /*
   * Initializes the place to store the public and private key pairs.
   */
  init: function() {
    this._init_migration_table();
    var db_version = this._get_version();
    this.version = (db_version) ? db_version : this.set_version(BASE_VERSION);
    this.manager = Manager(this);

    this.manager.add_migration("Create keys table", this._create_table_migration("keys", { id: "INTEGER PRIMARY KEY", public_key: "TEXT", private_key: "TEXT", created: "TEXT" }));
    this.manager.add_migration("Create sites table", this._create_table_migration("sites", { id: "INTEGER PRIMARY KEY", domain: "TEXT UNIQUE" }));
    this.manager.add_migration("Create key_sites table", this._create_table_migration("key_sites", { key_id: "NUMERIC", site_id: "NUMERIC" }));
    this.manager.add_migration("Create password_verify table", this._create_table_migration("password_verify", { hash: "TEXT" }));
    this.manager.migrate();
  },

  /**
   * Checks to see if the key_id is already assigned to a domain.
   *
   * @param {integer} key_id the key id to check
   * @return {bool} true if the key is assigned already; false otherwise
   */
  is_key_assigned: function(key_id) {
    var result = false;
    this._execute("SELECT * FROM keys_sites WHERE key_id=:key_id", function(statement) {
      statement.params.key_id = key_id;
      if (statement.executeStep()) {
        result = (statement.row.key_id) ? true : false;
      }
    });
    return result;
  },

  /*
   * Returns true if the master password has been set before.
   *
   * @return boolean
   */
  is_password_set: function() {
    return this.get_stored_hash() !== null;
  },

  /**
   * Resets the database to before any migrations were applied.
   *
   * @return {bool} true on success, false if there was an error
   */
  reset: function() {
    return this._drop_table("keys") &&
           this._drop_table("sites") &&
           this._drop_table("keys_sites") &&
           this._drop_table("password_verify");
  },

  /**
   * Sets the version number of the database.
   *
   * @param {int} version the new version number of the database
   * @return {int} version if update was successful, null if there was an error
   */
  set_version: function(version) {
    var db = this;
    var sql = '';
    if (this._get_version() !== null) {
      sql = "UPDATE migrations SET version=:version";
    } else {
      sql = "INSERT INTO migrations (version) VALUES (:version)";
    }
    return this._execute(sql, function(statement) {
      statement.params.version = version;
      statement.execute();
      db.version = version;
    }) ? this.version : null;
  },

  /**
   * Stores a cache key in the database for future use.
   *
   * @param {forge key objects} keys the key pair to store as the next cache key.
   */
  store_cache_pair: function(public_key, private_key) {
    return this._execute("INSERT INTO keys (public_key, private_key, created) VALUES(:public_key, :private_key, :created)", function(statement) {
      statement.params.public_key  = public_key;
      statement.params.private_key = private_key;
      statement.params.created     = utils.get_time();
      statement.execute();
    });
  },

  /*
   * This function stores the key in the browser's password manager
   *
   * @param key the key to store
   */
  store_encryption_key: function(key) {
    var _this = this;
    if (! this.is_password_set()) {
      return this._execute("INSERT OR ABORT INTO password_verify (hash) VALUES(:hash)", function(statement) {
        statement.params.hash = _this.get_storage_hash(key);
        statement.execute();
      });
    }
    return false;
  },

  /**
   * Executes the database query to create a new table.
   *
   * @param {string} name the name of the table to drop
   * @param {hash} columns hash of columns contained in the table to allow recreation of the table. See create_table() for example
   * @return {bool} true on success, false if there was an error
   */
  _create_table: function(name, columns) {
    return this._execute("CREATE TABLE " + name + " (" + this._serialize(columns) + ")");
  },

  /**
   * Creates the two migration functions for a create_table migration.
   *
   * @param {string} name the name of the new table
   * @param {hash} columns hash of columns where the key is the column name and the value is the type and any constraints
   *                       EXAMPLE: { name: "TEXT UNIQUE NOT NULL" }
   * @return {hash} hash containing the up and down functions needed for this migration
   */
  _create_table_migration: function(name, columns) {
    return {
      up: function(db) { return db._create_table(name, columns); },
      down: function(db) { return db._drop_table(name); },
    };
  },

  /**
   * Executes the database query to drop a table.
   *
   * @param {string} name the name of the table to drop
   * @return {bool} true on success, false if there was an error
   */
  _drop_table: function(name) {
    return this._execute("DROP TABLE " + name);
  },

  /**
   * Creates the two migration functions for a drop_table migration.
   *
   * @param {string} name the name of the table to drop
   * @param {hash} columns hash of columns contained in the table to allow recreation of the table. See create_table() for example
   * @return {hash} hash containing the up and down functions needed for this migration
   */
  _drop_table_migration: function(name, columns) {
    return {
      up: function(db) { return db._drop_table(name); },
      down: function(db) { return db._create_table(name, columns); },
    };
  },

  /**
   * This function wraps some SQL execution in the try...catch...finally and returns a boolean
   * result on success or failure.
   *
   * @param {string} sql string of SQL code to pass to createStatement
   * @param {function(statement, db)} statement_handler a function that takes the statement and db connection as parameters and does stuff with the statement
   * @return {bool} true on success, false if there was an error
   */
  _execute: function(sql, statement_handler) {
    var db = this.connect();

    var result = false;
    try {
      var statement = db.createStatement(sql);
      if (statement_handler) { statement_handler(statement, db); }
      else { statement.execute(); }
      result = true;
    } catch (e) {
      utils.dump(e);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }
    return result;
  },

  /**
   * Fetches the database version number from the database.
   *
   * @return {int} the current migration version of the database
   */
  _get_version: function() {
    var version = null;
    this._execute("SELECT version FROM migrations", function(statement) {
      if (statement.executeStep()) {
        version = statement.row.version;
      }
    });
    return version;
  },

  /**
   * Creates the migrations table if it does not exist.
   *
   * @return {bool} true if the SQL query successfully executed, false if there was an error. NOTE: if the table
   *                already exists it will still return true.
   */
  _init_migration_table: function() {
    return this._execute("CREATE TABLE IF NOT EXISTS migrations (version NUMERIC)");
  },

  /**
   * Converts a key value pair hash into a string. Keys and values are separated by a space and pairs are separated by a comma.
   *
   * @param {hash} hash the hash to serialize
   * @return {string} string of the serialized hash
   */
  _serialize: function(hash) {
    var r = [];
    for (key in hash) {
      r.push(key + " " + hash[key]);
    }
    return r.join(',');
  },
};
