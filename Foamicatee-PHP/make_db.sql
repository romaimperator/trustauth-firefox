DROP database IF EXISTS foamicate;
CREATE database foamicate;
USE foamicate;

create table users
(
id integer primary key auto_increment,
public_key text not null
) ENGINE=INNODB;

create table note
(
id integer primary key auto_increment,
note text not null,
user_id integer not null,
foreign key (user_id) references users (id)
) ENGINE=INNODB;
