#!/bin/zsh

upload_file(){
	if [ $# -ne 2 ]
	then
		echo echo 'useage ./client [upload [filename]] [download [secret_key uuid]] url'
		return 1
	else
	file=$(cat $1)
		curl -XPOST --data \'$file\' $2/encrypt
	fi
}

download_file(){
	if [ $# -ne 3 ]
	then
		echo 'useage ./client [upload [filename]] [download [secret_key uuid]] url'
		return 1
	else
		json={\"secret_key\":\"$1\",\"uuid\":\"$2\"}
		#echo \'$json\'
		echo curl -XPOST --data \'$json\' $3/retrieve | zsh
	fi
}

if [ $# -lt 3 ]
then
	echo 'useage ./client [upload [filename]] [download [secret_key uuid]] url'
	return 1
else
	if [ $1 = 'upload' ]
	then
		echo UPLOAD
		upload_file $2 $3
	elif [ $1 = 'download' ]
	then
		echo DOWNLOAD
		download_file $2 $3 $4
	else
		echo $1 'is an invalid option'
		return 1
	fi
fi
