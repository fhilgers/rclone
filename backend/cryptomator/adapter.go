package cryptomator

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/object"
)

// Adapts a the Rclone fs.Fs interface to the Fs defined
// by cryptomator for operations on the vault
func NewCryptomatorAdapterFs(ctx context.Context, f fs.Fs) *CryptomatorAdapterFs {
  return &CryptomatorAdapterFs{
    f: f,
    ctx: ctx,
  }
}


type CryptomatorAdapterFs struct {
  f fs.Fs
  ctx context.Context
}


// Open a file for reading, generally this is used to
// read the directory id from their dir.id files
func (f *CryptomatorAdapterFs) Open(name string) (io.ReadCloser, error) {
	obj, err := f.f.NewObject(f.ctx, name)
	if err != nil {
		return nil, err
	}

	return obj.Open(f.ctx)
}

type wrapPipeWriter struct {
	*io.PipeWriter

	chanErr chan (error)
}

func (w *wrapPipeWriter) Close() error {
	err := w.PipeWriter.Close()
	if err != nil {
		return err
	}

	return <-w.chanErr
}

// Create a new file for writing, generally this is used to
// write new directory ids and to write dirid.c9r directory id 
// backup files
// This should fail if the file already exists
func (f *CryptomatorAdapterFs) Create(name string) (io.WriteCloser, error) {
	if b, err := fs.FileExists(f.ctx, f.f, name); b {
		return nil, fmt.Errorf("file exists: %s", name)
	} else if err != nil {
		return nil, err
	}

	pipeReader, pipeWriter := io.Pipe()

	info := object.NewStaticObjectInfo(name, time.Now(), -1, true, nil, f.f)

	chanErr := make(chan (error))
	go func() {
		_, err := f.f.Put(f.ctx, pipeReader, info)
		chanErr <- err
	}()

	return &wrapPipeWriter{
		PipeWriter: pipeWriter,
		chanErr:    chanErr,
	}, nil
}

// Remove a directory at a path
// This should fail if the directory is not empty
func (f *CryptomatorAdapterFs) RemoveDir(name string) error {
	if f.f.Features().BucketBased {
		entries, err := f.f.List(f.ctx, name)
		if err != nil {
			return err
		}
		if len(entries) > 0 {
			return fs.ErrorDirectoryNotEmpty
		}
	}
	return f.f.Rmdir(f.ctx, name)
}

// Remove a file at a path
// This should fail if the file does not exist
func (f *CryptomatorAdapterFs) RemoveFile(name string) error {
	obj, err := f.f.NewObject(f.ctx, name)
	if err != nil {
		return err
	}

	return obj.Remove(f.ctx)
}

// Make a directory with all parent directories
// This should not fail if the directory already exists
func (f *CryptomatorAdapterFs) MkdirAll(name string) error {
	return f.f.Mkdir(f.ctx, name)
}
